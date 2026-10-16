<#
    Bring up the whole local ION estate in dependency order: Elasticsearch and
    Kibana, OpenCTI, TIDE, then ION itself.

    These are four independent compose projects, not one. ION reaches the other
    three over host.docker.internal (cross-compose DNS does not resolve service
    names), so each external stack has to be listening before ION's startup
    probes run -- hence the ordering and the waits.

    Two steps exist only because the stack does not come up correctly without
    them, and both are easy to forget by hand:

      * Kibana authenticates to Elasticsearch as kibana_system, but compose
        only sets the bootstrap password for the `elastic` user. On a fresh
        Elasticsearch volume kibana_system has no usable password and Kibana
        401s forever. The POST below sets it; it is idempotent, so it also runs
        harmlessly against an existing cluster.

      * TIDE's external API (which ION calls with X-TIDE-API-KEY) validates the
        key against its database and then looks up the tenants of the key's
        owner. With AUTH_DISABLED=true every TIDE request resolves to the
        synthetic user `dev-user-001`, which is not a database row and has no
        tenant, so a key minted through TIDE's own settings UI returns an empty
        client list and ION gets 403 "API key owner has no tenant access".
        Assigning that user to the default tenant fixes it, and the assignment
        is an upsert, so re-running is free.

    Waits are on readiness, not on `docker compose up` returning. Compose
    returning means the container was created; Elasticsearch recovering shards
    and Kibana running saved-object migrations both take substantially longer,
    and ION started against a half-ready estate is the failure this script is
    meant to stop.

    Elasticsearch is considered ready at green OR at yellow with no unassigned
    primaries. A single-node cluster holding replica-1 indices stays yellow
    permanently -- waiting for green would hang forever on a healthy estate.

    The Elasticsearch password is read out of test-elasticsearch's compose file
    rather than duplicated here, so there is one place to change it. It is used
    in request headers and never printed.

    Arkime and GitLab are deliberately not started: they are not part of this
    estate's integration set. Ollama is opt-in via -WithAI, which adds the
    main compose file's `ai` profile.

    Which Elasticsearch data this brings up is NOT decided here. compose takes
    its project name from the directory, so test-elasticsearch gets an empty
    `test-elasticsearch_elasticsearch-data` unless a local
    test-elasticsearch/docker-compose.override.yml redeclares
    `elasticsearch-data` as external. The populated volume on this estate is
    `ion_elasticsearch-data` (~149 primaries), holding the security alerts and
    the Kibana cases that ION's `alert_cases.kibana_case_id` rows point at; on
    an empty volume ION's 15s Kibana sync loop 404s on every one of them.
    Override files are gitignored by project policy, so a fresh clone starts
    empty by design -- write the override if you want the existing data.

    Expect Elasticsearch to sit at yellow: one node with replica-1 indices
    leaves every replica unassigned, which is why this script treats yellow
    with no unassigned primaries as ready.

    Examples:
      ./scripts/start-stack.ps1                  # bring everything up
      ./scripts/start-stack.ps1 -WithAI          # ... including Ollama
      ./scripts/start-stack.ps1 -Status          # report, change nothing
      ./scripts/start-stack.ps1 -Stop            # stop all four projects
#>
param(
    # Where the TIDE checkout lives. TIDE is its own repository, not a
    # subdirectory of this one.
    [string]$TidePath = (Join-Path $HOME 'TIDE'),

    # Per-wait ceiling. Elasticsearch shard recovery on a populated volume and
    # OpenCTI's first GraphQL schema build are the two that get near this.
    [int]$TimeoutSec = 420,

    [switch]$WithAI,
    [switch]$Stop,
    [switch]$Status,

    [switch]$SkipElastic,
    [switch]$SkipOpenCTI,
    [switch]$SkipTide,
    [switch]$SkipIon
)

$ErrorActionPreference = 'Stop'

$RepoRoot    = Split-Path -Parent $PSScriptRoot
$ElasticDir  = Join-Path $RepoRoot 'test-elasticsearch'
$OpenCtiDir  = Join-Path $RepoRoot 'test-opencti'

# TIDE's default tenant and the synthetic user AUTH_DISABLED resolves to. See
# the header note on why the assignment is needed.
$TideDevUser = 'dev-user-001'

function Write-Step  { param([string]$m) Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok    { param([string]$m) Write-Host "    ok    $m" -ForegroundColor Green }
function Write-Warn2 { param([string]$m) Write-Host "    warn  $m" -ForegroundColor Yellow }
function Write-Fail  { param([string]$m) Write-Host "    FAIL  $m" -ForegroundColor Red }

# Every request goes through curl.exe rather than Invoke-WebRequest. TIDE's
# nginx serves a self-signed CN=tide.local certificate, and PowerShell 5.1 --
# which is what is installed here -- has no -SkipCertificateCheck. The
# alternative on 5.1 is mutating the process-global
# ServicePointManager.ServerCertificateValidationCallback, which would disable
# certificate validation for every request the script makes, not just TIDE's.
# curl takes -k per call, so the exception stays where it belongs.
#
# System32's curl is preferred over whatever is first on PATH, so a Git or
# MSYS curl earlier in PATH does not change the script's behaviour.
$script:CurlExe = if (Test-Path "$env:SystemRoot\System32\curl.exe") {
    "$env:SystemRoot\System32\curl.exe"
} else {
    (Get-Command curl.exe -ErrorAction Stop).Source
}

function Invoke-Http {
    <#
        Returns a hashtable: Ok, Code, Body. Never throws on an HTTP error
        status -- callers treat a 401 or a 503 as "not ready yet", which is
        different from "the request could not be made at all". Ok is true only
        for 2xx, so a caller can test readiness without reading Code.
    #>
    param(
        [string]$Uri,
        [string]$Method = 'GET',
        [hashtable]$Headers,
        [string]$Body,
        [string]$ContentType = 'application/json',
        [switch]$Insecure,
        [int]$TimeoutSec = 20
    )

    # --write-out puts the status code on stdout; the body goes to a file, so
    # the two never have to be separated by parsing.
    $bodyFile = [IO.Path]::GetTempFileName()
    # No --show-error: a connection refused or an empty reply while a service
    # is still booting is the normal case here, and the caller reads it off
    # Code rather than off curl's stderr.
    $curlArgs = @(
        '--silent',
        '--request', $Method,
        '--max-time', "$TimeoutSec",
        '--output', $bodyFile,
        '--write-out', '%{http_code}'
    )
    if ($Insecure) { $curlArgs += '--insecure' }
    foreach ($k in $Headers.Keys) { $curlArgs += @('--header', "${k}: $($Headers[$k])") }

    $payloadFile = $null
    if ($PSBoundParameters.ContainsKey('Body')) {
        # @file rather than inline: keeps JSON braces and quotes away from
        # PowerShell's and curl's argument parsing.
        $payloadFile = [IO.Path]::GetTempFileName()
        [IO.File]::WriteAllText($payloadFile, $Body)
        $curlArgs += @('--header', "Content-Type: $ContentType", '--data', "@$payloadFile")
    }
    $curlArgs += $Uri

    # Same PowerShell 5.1 trap as Invoke-Compose: anything curl writes to
    # stderr becomes an error record, and under ErrorActionPreference=Stop a
    # service that is merely still booting would abort the script instead of
    # being retried. curl's exit code and the written status code carry the
    # verdict, so the preference is relaxed for the call only.
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $code = (& $script:CurlExe @curlArgs 2>$null | Select-Object -Last 1)
        $ErrorActionPreference = $previousPreference

        $text = if (Test-Path $bodyFile) { [IO.File]::ReadAllText($bodyFile) } else { '' }
        $n = 0
        [void][int]::TryParse(("$code").Trim(), [ref]$n)
        return @{ Ok = ($n -ge 200 -and $n -lt 300); Code = $n; Body = $text }
    } finally {
        $ErrorActionPreference = $previousPreference
        Remove-Item $bodyFile -ErrorAction SilentlyContinue
        if ($payloadFile) { Remove-Item $payloadFile -ErrorAction SilentlyContinue }
    }
}

function Wait-For {
    <#
        Poll $Test until it returns $true. $Test returns a bare boolean; any
        detail it wants to report it prints itself.
    #>
    param(
        [string]$What,
        [scriptblock]$Test,
        [int]$TimeoutSec = $script:TimeoutSec,
        [int]$IntervalSec = 5
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $spun = $false
    while ((Get-Date) -lt $deadline) {
        if (& $Test) {
            if ($spun) { Write-Host '' }
            return $true
        }
        Write-Host '.' -NoNewline
        $spun = $true
        Start-Sleep -Seconds $IntervalSec
    }
    if ($spun) { Write-Host '' }
    Write-Fail "$What did not become ready within ${TimeoutSec}s"
    return $false
}

function Get-ElasticPassword {
    <#
        Single source of truth: the ELASTIC_PASSWORD line in
        test-elasticsearch/docker-compose.yml, which is what actually
        bootstrapped the cluster.
    #>
    $composeFile = Join-Path $ElasticDir 'docker-compose.yml'
    if (-not (Test-Path $composeFile)) { throw "not found: $composeFile" }
    $line = Select-String -Path $composeFile -Pattern 'ELASTIC_PASSWORD=(.+)$' |
            Select-Object -First 1
    if (-not $line) { throw "no ELASTIC_PASSWORD in $composeFile" }
    return $line.Matches[0].Groups[1].Value.Trim()
}

function Get-BasicAuthHeader {
    param([string]$User, [string]$Password)
    $pair = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${User}:${Password}"))
    return @{ Authorization = "Basic $pair" }
}

function Invoke-Compose {
    param([string]$Dir, [string[]]$ComposeArgs)

    # PowerShell 5.1 turns a native command's stderr into an error record, and
    # docker compose writes all of its progress there -- including the harmless
    # "`version` is obsolete" notice from test-elasticsearch's compose file.
    # Under ErrorActionPreference=Stop that aborts the script on a command that
    # actually succeeded, so the preference is relaxed around the call and the
    # real verdict comes from the exit code.
    $previousPreference = $ErrorActionPreference
    Push-Location $Dir
    try {
        $ErrorActionPreference = 'Continue'
        $output = & docker compose @ComposeArgs 2>&1
        $exit = $LASTEXITCODE
        $ErrorActionPreference = $previousPreference

        $output | ForEach-Object { Write-Verbose "$_" }
        if ($exit -ne 0) {
            # On a real failure the compose output is the only useful diagnosis.
            $output | ForEach-Object { Write-Host "          $_" -ForegroundColor DarkGray }
            throw "docker compose $($ComposeArgs -join ' ') failed in $Dir (exit $exit)"
        }
    } finally {
        $ErrorActionPreference = $previousPreference
        Pop-Location
    }
}

function Test-DockerUp {
    & docker version --format '{{.Server.Version}}' *> $null
    return ($LASTEXITCODE -eq 0)
}

# ---------------------------------------------------------------------------
# Docker daemon
# ---------------------------------------------------------------------------

function Start-DockerIfNeeded {
    if (Test-DockerUp) { Write-Ok 'docker daemon responding'; return $true }

    $exe = 'C:\Program Files\Docker\Docker\Docker Desktop.exe'
    if (-not (Test-Path $exe)) {
        Write-Fail "docker daemon not responding and Docker Desktop not found at $exe"
        return $false
    }
    Write-Warn2 'docker daemon not responding; starting Docker Desktop'
    Start-Process -FilePath $exe | Out-Null

    # Docker Desktop's engine can take well over a minute from cold.
    return (Wait-For -What 'docker daemon' -TimeoutSec 240 -Test { Test-DockerUp })
}

# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------

function Start-Elastic {
    param([string]$EsPassword)

    Write-Step 'Elasticsearch + Kibana (test-elasticsearch)'
    $auth = Get-BasicAuthHeader -User 'elastic' -Password $EsPassword

    # Named explicitly: this compose file also defines an `arkime` service,
    # which is not part of this estate and would be built from source.
    Invoke-Compose -Dir $ElasticDir -ComposeArgs @('up', '-d', 'elasticsearch')

    $ready = Wait-For -What 'Elasticsearch' -Test {
        $r = Invoke-Http -Uri 'http://localhost:9200/_cluster/health' -Headers $auth
        if (-not $r.Ok) { return $false }
        $h = $r.Body | ConvertFrom-Json
        # Yellow is terminal on one node with replica-1 indices; what matters
        # is that no primary is missing.
        return ($h.status -eq 'green') -or
               ($h.status -eq 'yellow' -and [int]$h.unassigned_primary_shards -eq 0)
    }
    if (-not $ready) { return $false }

    $h = (Invoke-Http -Uri 'http://localhost:9200/_cluster/health' -Headers $auth).Body | ConvertFrom-Json
    Write-Ok "Elasticsearch $($h.status), $($h.active_primary_shards) primaries"

    # The gotcha from the header: give kibana_system the password Kibana's
    # compose environment already expects.
    $set = Invoke-Http -Uri 'http://localhost:9200/_security/user/kibana_system/_password' `
                       -Method 'POST' -Headers $auth `
                       -Body (@{ password = $EsPassword } | ConvertTo-Json -Compress)
    if ($set.Ok) { Write-Ok 'kibana_system password set' }
    else { Write-Warn2 "could not set kibana_system password (HTTP $($set.Code)); Kibana may 401" }

    Invoke-Compose -Dir $ElasticDir -ComposeArgs @('up', '-d', 'kibana')

    $ready = Wait-For -What 'Kibana' -Test {
        $r = Invoke-Http -Uri 'http://localhost:5601/api/status' -Headers $auth
        if (-not $r.Ok) { return $false }
        return (($r.Body | ConvertFrom-Json).status.overall.level -eq 'available')
    }
    if ($ready) { Write-Ok 'Kibana available' }
    return $ready
}

function Start-OpenCti {
    Write-Step 'OpenCTI (test-opencti)'
    Invoke-Compose -Dir $OpenCtiDir -ComposeArgs @('up', '-d')

    # The platform serves the app only once its GraphQL schema is built, which
    # is the point a caller can actually use it.
    $ready = Wait-For -What 'OpenCTI platform' -Test {
        (Invoke-Http -Uri 'http://localhost:8888/').Code -eq 200
    }
    if ($ready) { Write-Ok 'OpenCTI platform serving on 8888' }
    return $ready
}

function Start-Tide {
    Write-Step 'TIDE'
    if (-not (Test-Path $TidePath)) {
        Write-Fail "TIDE checkout not found at $TidePath (pass -TidePath)"
        return $false
    }

    # nginx bind-mounts these as files. If they are missing, Docker creates
    # directories in their place and nginx dies on PEM_read_bio_X509_AUX().
    foreach ($cert in @('server.crt', 'server.key', 'ca.crt')) {
        $p = Join-Path $TidePath (Join-Path 'certs' $cert)
        if (-not (Test-Path $p -PathType Leaf)) {
            Write-Fail "TIDE certificate missing or not a file: $p"
            Write-Host '          Generate real certs before starting TIDE, or nginx will not boot.'
            return $false
        }
    }

    Invoke-Compose -Dir $TidePath -ComposeArgs @('up', '-d')

    $ready = Wait-For -What 'TIDE' -Test {
        (Invoke-Http -Uri 'https://localhost/health' -Insecure).Code -eq 200
    }
    if (-not $ready) { return $false }
    Write-Ok 'TIDE healthy behind nginx on 443'

    # The second gotcha from the header: without this, ION's TIDE calls 403.
    $r = Invoke-Http -Uri 'https://localhost/api/clients' -Insecure
    if (-not $r.Ok) {
        Write-Warn2 "could not list TIDE clients (HTTP $($r.Code)); skipping tenant assignment"
        return $true
    }

    $clients = @($r.Body | ConvertFrom-Json)
    if ($clients.Count -eq 0) {
        Write-Warn2 'TIDE has no tenants; create one in TIDE before ION can query it'
        return $true
    }

    $target = $clients | Where-Object { $_.is_default } | Select-Object -First 1
    if (-not $target) { $target = $clients[0] }

    $assign = Invoke-Http -Uri "https://localhost/api/clients/$($target.id)/users" `
                          -Method 'POST' -Insecure `
                          -Body (@{ user_id = $TideDevUser; is_default = $true } | ConvertTo-Json -Compress)
    if ($assign.Ok) {
        Write-Ok "$TideDevUser assigned to tenant '$($target.name)' ($($target.id))"
        Write-Host "          tide_client_id = $($target.id)" -ForegroundColor DarkGray
    } else {
        Write-Warn2 "tenant assignment failed (HTTP $($assign.Code)); ION's TIDE calls may 403"
    }
    return $true
}

function Start-Ion {
    Write-Step 'ION core (postgres + ion + seeder)'
    $composeArgs = @('up', '-d')
    if ($WithAI) { $composeArgs = @('--profile', 'ai') + $composeArgs }
    Invoke-Compose -Dir $RepoRoot -ComposeArgs $composeArgs

    $ready = Wait-For -What 'ION' -Test {
        $r = Invoke-Http -Uri 'http://localhost:8000/api/health'
        if ($r.Code -ne 200) { return $false }
        return (($r.Body | ConvertFrom-Json).status -eq 'ok')
    }
    if (-not $ready) { return $false }

    $h = (Invoke-Http -Uri 'http://localhost:8000/api/health').Body | ConvertFrom-Json
    Write-Ok "ION $($h.version) on $($h.database)"
    return $true
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

function Show-Summary {
    param([string]$EsPassword)

    Write-Step 'Estate'
    $auth = Get-BasicAuthHeader -User 'elastic' -Password $EsPassword

    $rows = @(
        @{ Name = 'Elasticsearch'; Url = 'http://localhost:9200';  Probe = {
                $r = Invoke-Http -Uri 'http://localhost:9200/_cluster/health' -Headers $auth
                if ($r.Code -ne 200) { return "unreachable (HTTP $($r.Code))" }
                $h = $r.Body | ConvertFrom-Json
                "$($h.status), $($h.active_primary_shards) primaries"
            } },
        @{ Name = 'Kibana'; Url = 'http://localhost:5601'; Probe = {
                $r = Invoke-Http -Uri 'http://localhost:5601/api/status' -Headers $auth
                if ($r.Code -ne 200) { return "unreachable (HTTP $($r.Code))" }
                $s = $r.Body | ConvertFrom-Json
                "$($s.status.overall.level), v$($s.version.number)"
            } },
        @{ Name = 'OpenCTI'; Url = 'http://localhost:8888'; Probe = {
                $r = Invoke-Http -Uri 'http://localhost:8888/'
                if ($r.Code -ne 200) { return "unreachable (HTTP $($r.Code))" }
                'serving'
            } },
        @{ Name = 'TIDE'; Url = 'https://localhost'; Probe = {
                $r = Invoke-Http -Uri 'https://localhost/health' -Insecure
                if ($r.Code -ne 200) { return "unreachable (HTTP $($r.Code))" }
                'healthy'
            } },
        @{ Name = 'ION'; Url = 'http://localhost:8000'; Probe = {
                $r = Invoke-Http -Uri 'http://localhost:8000/api/health'
                if ($r.Code -ne 200) { return "unreachable (HTTP $($r.Code))" }
                $h = $r.Body | ConvertFrom-Json
                "$($h.status), v$($h.version) on $($h.database)"
            } }
    )

    foreach ($row in $rows) {
        $detail = & $row.Probe
        $colour = if ($detail -like 'unreachable*') { 'Red' } else { 'Green' }
        Write-Host ('    {0,-14} {1,-24} {2}' -f $row.Name, $row.Url, $detail) -ForegroundColor $colour
    }

    Write-Host ''
    Write-Host '    ION integrations page: http://localhost:8000/integrations' -ForegroundColor DarkGray
    Write-Host '    Deeper per-integration probe: python scripts/stack_monitor.py' -ForegroundColor DarkGray
}

function Stop-Estate {
    Write-Step 'Stopping the estate (volumes are kept)'
    # Reverse dependency order, so ION is not left talking to vanished services.
    $targets = @(
        @{ Name = 'ION core';  Dir = $RepoRoot },
        @{ Name = 'TIDE';      Dir = $TidePath },
        @{ Name = 'OpenCTI';   Dir = $OpenCtiDir },
        @{ Name = 'Elastic';   Dir = $ElasticDir }
    )
    foreach ($t in $targets) {
        if (-not (Test-Path $t.Dir)) { Write-Warn2 "$($t.Name): $($t.Dir) not found, skipped"; continue }
        try {
            Invoke-Compose -Dir $t.Dir -ComposeArgs @('stop')
            Write-Ok "$($t.Name) stopped"
        } catch {
            Write-Warn2 "$($t.Name): $($_.Exception.Message)"
        }
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if (-not (Start-DockerIfNeeded)) { exit 1 }

$esPassword = Get-ElasticPassword

if ($Stop) {
    Stop-Estate
    exit 0
}

if ($Status) {
    Show-Summary -EsPassword $esPassword
    exit 0
}

$failed = @()

if (-not $SkipElastic) { if (-not (Start-Elastic -EsPassword $esPassword)) { $failed += 'Elasticsearch/Kibana' } }
if (-not $SkipOpenCTI) { if (-not (Start-OpenCti))                        { $failed += 'OpenCTI' } }
if (-not $SkipTide)    { if (-not (Start-Tide))                           { $failed += 'TIDE' } }

# ION last: its startup probes expect the integrations to be answering.
if (-not $SkipIon)     { if (-not (Start-Ion))                            { $failed += 'ION' } }

Show-Summary -EsPassword $esPassword

if ($failed.Count -gt 0) {
    Write-Host ''
    Write-Fail "did not come up: $($failed -join ', ')"
    exit 1
}

Write-Host ''
Write-Host 'Estate up.' -ForegroundColor Green
exit 0
