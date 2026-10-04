<#
    Copy the running instance's effective settings into config.json via the
    admin API, so that removing keys from .env does not fall back to whatever
    config.json last held. Order matters: config.json predates the current
    Elasticsearch settings, so pruning .env first would silently revert live
    integrations to September's values.

    Run with -DryRun first. It prints every PUT it would make and writes no
    settings. (It still logs in to read the config, which creates and then
    closes one admin session.)

    Authentication: ION does not accept HTTP Basic. The script logs in at
    POST /api/auth/login, takes the session token from the Set-Cookie header,
    and sends it as "Authorization: Bearer <token>" with no cookie, which is
    the form the CSRF middleware exempts. The password and the token are never
    printed.

    Secrets are never migrated. GET /config returns them masked, so any field
    whose name looks secret, and every *_set flag, is dropped from each payload.
    The PUT handlers also ignore values starting with "*", but the script does
    not rely on that.
#>
param(
    [string]$BaseUrl = "http://localhost:8000",
    [string]$Username = "admin",
    [Parameter(Mandatory = $true)][string]$AdminPassword,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$BaseUrl = $BaseUrl.TrimEnd("/")

# Only sections with a PUT endpoint. "sources" and "config_path" are not
# sections and have no PUT endpoint, so a whitelist keeps them out.
$sections = @("general", "elasticsearch", "kibana", "gitlab", "opencti",
              "arkime", "tide", "ollama", "oidc", "dfir_iris",
              "abuseipdb", "virustotal")

# Fields present in GET /config that the PUT models do not accept.
$readOnlyFields = @("db_path")

function Get-ErrorDetail($err) {
    # Windows PowerShell 5.1 keeps the HTTP body on the response stream.
    $status = ""
    $detail = ""
    try {
        $resp = $err.Exception.Response
        if ($null -ne $resp) {
            $status = [int]$resp.StatusCode
            $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
            $text = $reader.ReadToEnd()
            $reader.Close()
            $json = $text | ConvertFrom-Json
            if ($null -ne $json.detail) { $detail = [string]$json.detail }
        }
    } catch {
        # Fall through with whatever we have.
    }
    if ($status -ne "") { return "HTTP $status $detail".Trim() }
    return $err.Exception.Message
}

# ---- Log in -----------------------------------------------------------------
$loginBody = ConvertTo-Json -InputObject @{ username = $Username; password = $AdminPassword }
$token = $null
try {
    $login = Invoke-WebRequest -UseBasicParsing -Method Post `
        -Uri "$BaseUrl/api/auth/login" -ContentType "application/json" `
        -Body ([Text.Encoding]::UTF8.GetBytes($loginBody))
    $cookieHeader = [string]$login.Headers["Set-Cookie"]
    $m = [regex]::Match($cookieHeader, "ion_session=([^;,\s]+)")
    if ($m.Success) { $token = $m.Groups[1].Value }
} catch {
    Write-Warning ("Login failed: " + (Get-ErrorDetail $_))
    exit 1
}
$loginBody = $null
if ($null -eq $token) {
    Write-Warning "Login succeeded but no ion_session cookie was returned."
    exit 1
}
$auth = @{ Authorization = "Bearer $token" }

$failed = 0
try {
    $effective = Invoke-RestMethod -Uri "$BaseUrl/api/admin/config" -Headers $auth
    $present = @($effective.PSObject.Properties.Name)

    foreach ($section in $sections) {
        if ($present -notcontains $section) {
            Write-Host "skip   $section (not present in GET /config)"
            continue
        }

        # Strip secret fields. GET /config returns them masked, so writing them
        # back would store the mask itself. Secrets stay in .env and are never
        # sent by this script.
        $obj = $effective.$section
        $clean = [ordered]@{}
        $stripped = @()
        foreach ($prop in $obj.PSObject.Properties) {
            $name = $prop.Name
            if ($readOnlyFields -contains $name) { continue }
            if ($name -match '(password|token|api_key|secret)') { $stripped += $name; continue }
            if ($name -match '_set$') { $stripped += $name; continue }
            # An empty URL is "not configured". The PUT handlers run every URL
            # through an SSRF check that rejects "", which would fail the
            # whole section, so leave it out instead.
            if ($name -match '_url$' -and [string]::IsNullOrEmpty([string]$prop.Value)) {
                Write-Warning "$section.$name is empty, not sent. Check config.json holds no stale value for it."
                continue
            }
            $clean[$name] = $prop.Value
        }

        $payload = ConvertTo-Json -InputObject $clean -Depth 6 -Compress

        # Last line of defence: a masked value looks like a run of asterisks.
        if ($payload -match '\*{4,}') {
            Write-Warning "skip   $section : payload contains a masked-looking value, refusing to send"
            $failed++
            continue
        }

        if ($DryRun) {
            Write-Host "DRYRUN PUT /api/admin/config/$section"
            Write-Host "       stripped: $($stripped -join ', ')"
            Write-Host "       $payload"
            continue
        }

        try {
            Invoke-RestMethod -Method Put -Uri "$BaseUrl/api/admin/config/$section" `
                -Headers $auth -ContentType "application/json; charset=utf-8" `
                -Body ([Text.Encoding]::UTF8.GetBytes($payload)) | Out-Null
            Write-Host "wrote  $section"
        } catch {
            Write-Warning ("failed $section : " + (Get-ErrorDetail $_))
            $failed++
        }
    }
} catch {
    Write-Warning ("Could not read config: " + (Get-ErrorDetail $_))
    $failed++
} finally {
    # Close the session this script opened.
    try {
        Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/logout" -Headers $auth | Out-Null
    } catch {
        Write-Warning "Logout failed; the session will expire on its own."
    }
    $token = $null
    $auth = $null
}

if ($failed -gt 0) {
    Write-Host "$failed problem(s). See warnings above."
    exit 1
}
if ($DryRun) { Write-Host "Dry run complete. Nothing was written." }
