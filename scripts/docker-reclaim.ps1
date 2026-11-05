<#
    Reclaim Docker Desktop disk space on this machine, in the order that
    actually works: prune what nothing references, discard the freed blocks
    inside the VM, then compact the WSL disk so Windows gets the space back.

    Three phases, each skippable. The order is not arbitrary.

      1. Prune.   Stopped containers, orphaned anonymous volumes, dangling
                  images, unused build cache.
      2. Trim.    fstrim inside Docker's own mount namespace.
      3. Compact. Shut everything down and run Optimize-VHD elevated.

    Phase 2 is the step that is easy to leave out and expensive to leave out.
    Docker Desktop mounts its data disk at /mnt/docker-desktop-disk WITHOUT the
    `discard` option, so deleting an image frees the blocks inside ext4 but
    never hands them back to the .vhdx. Optimize-VHD compacts by finding blocks
    that are entirely zero; deleted ext4 data is not zeroed, so it sees garbage
    and leaves it alone. Measured on this machine 2026-10-22: compacting without
    the trim went 148.47 -> 107.37 GB and then stalled with ~17 GB it could not
    reach. Running fstrim first discarded 948 GiB of free blocks, and the next
    compaction took a further 13 GB (78.03 -> 64.97 GB).

    Named volumes are never pruned, and that is the whole reason this script
    deletes volumes by name instead of calling `docker volume prune`. Link count
    is not a safety signal: stopping a container drops its volumes to zero links,
    and on this estate 19 NAMED volumes sat at zero links at once -- among them
    agent-office_codex_auth, agent-office_claude_auth and agent-office_grok_auth
    (agent credentials), plus the external ion_elasticsearch-data that ION's
    alert_cases.kibana_case_id rows point at. `docker volume prune` spares those
    only because Docker 23+ defaults to anonymous-only; `--all` would destroy
    them. So the delete list is filtered to 64-hex anonymous names, the named
    list is snapshotted before and diffed after, and a diff is a hard failure.

    What this deliberately does NOT do: remove tagged images. Deciding that
    fubsxploitapps/ion:0.93.1 is dead while :0.99.11 is live needs a read of
    every image: pin, Dockerfile FROM and script reference across all the
    sibling checkouts, and a wrong guess throws away something unpullable (the
    public ixion36/ion was retired 2026-08-20). -ReportImages prints the
    candidates with their sizes; choosing among them stays a human call.

    Elevation is needed only for Optimize-VHD, so only that call is elevated,
    via a UAC prompt. WSL's own `--manage --set-sparse true` would avoid the
    whole dance but is refused as potentially corrupting, and is not forced here.

    Examples:
      ./scripts/docker-reclaim.ps1 -DryRun        # report, change nothing
      ./scripts/docker-reclaim.ps1                # all three phases
      ./scripts/docker-reclaim.ps1 -SkipCompact   # prune + trim, no shutdown
      ./scripts/docker-reclaim.ps1 -ReportImages  # tagged images by size, then exit
#>
param(
    [switch]$DryRun,

    [switch]$SkipPrune,
    [switch]$SkipTrim,
    [switch]$SkipCompact,

    # Print tagged images by unique size and exit. Advisory only -- see header.
    [switch]$ReportImages,

    # Prune even with containers running. Off by default: a running container
    # means a live stack, and its images and volumes are in use.
    [switch]$Force,

    [string]$VhdxPath = (Join-Path $env:LOCALAPPDATA 'Docker\wsl\disk\docker_data.vhdx'),

    [string]$DockerDesktop = 'C:\Program Files\Docker\Docker\Docker Desktop.exe',

    # Ceiling for waiting on the engine after a restart. Docker Desktop on a
    # cold WSL start is the one that gets near this.
    [int]$StartTimeoutSec = 300
)

$ErrorActionPreference = 'Stop'

function Write-Step  { param([string]$m) Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok    { param([string]$m) Write-Host "    ok    $m" -ForegroundColor Green }
function Write-Warn2 { param([string]$m) Write-Host "    warn  $m" -ForegroundColor Yellow }
function Write-Fail  { param([string]$m) Write-Host "    FAIL  $m" -ForegroundColor Red }
function Write-Info  { param([string]$m) Write-Host "    $m" }

# An anonymous volume's name is the 64-hex id Docker generates. Anything else
# was named by a compose file or a `docker volume create`, and is somebody's data.
$AnonPattern = '^[0-9a-f]{64}$'

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Engine {
    docker system df *> $null
    return ($LASTEXITCODE -eq 0)
}

function Get-VhdxGB {
    if (Test-Path $VhdxPath) { return [math]::Round((Get-Item $VhdxPath).Length / 1GB, 2) }
    return $null
}

function Get-NamedVolumes {
    @(docker volume ls -q) | Where-Object { $_ -and $_ -notmatch $AnonPattern } | Sort-Object
}

# docker prints sizes as "2.475GB" / "535.4MB" / "9.874kB" / "32B", decimal
# multipliers throughout. Returns bytes so the report can sort numerically.
function ConvertFrom-DockerSize {
    param([string]$Size)
    if ($Size -notmatch '^\s*([0-9.]+)\s*([kMGTP]?B)\s*$') { return 0 }
    $n = [double]$Matches[1]
    switch ($Matches[2]) {
        'B'  { return $n }
        'kB' { return $n * 1e3 }
        'MB' { return $n * 1e6 }
        'GB' { return $n * 1e9 }
        'TB' { return $n * 1e12 }
        'PB' { return $n * 1e15 }
    }
    return 0
}

function Wait-Engine {
    param([int]$TimeoutSec)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (Test-Engine) { return $true }
        Start-Sleep -Seconds 5
    }
    return $false
}

function Start-Engine {
    if (Test-Engine) { return }
    if (-not (Test-Path $DockerDesktop)) {
        throw "Docker Desktop not found at $DockerDesktop (pass -DockerDesktop)"
    }
    Write-Info 'starting Docker Desktop'
    Start-Process $DockerDesktop | Out-Null
    if (-not (Wait-Engine -TimeoutSec $StartTimeoutSec)) {
        throw "engine did not come up within ${StartTimeoutSec}s"
    }
}

# ---------------------------------------------------------------- preflight

Start-Engine
Write-Step 'Before'
docker system df
$vhdxBefore = Get-VhdxGB
if ($null -eq $vhdxBefore) {
    Write-Warn2 "no .vhdx at $VhdxPath -- compaction will be skipped"
} else {
    Write-Info ("vhdx {0} GB" -f $vhdxBefore)
}

if ($ReportImages) {
    Write-Step 'Images by unique size (advisory -- nothing is removed)'

    # Sorting has to be on bytes, not on docker's own strings: "535.4MB" sorts
    # above "2.475GB" lexically, which would put the report in the wrong order.
    $fmt = '{{range .Images}}{{.UniqueSize}}|{{.Size}}|{{.Repository}}:{{.Tag}}|{{.ID}}' + "`n" + '{{end}}'
    docker system df -v --format $fmt |
        Where-Object { $_ } |
        ForEach-Object {
            $p = $_ -split '\|'
            [pscustomobject]@{
                Bytes  = ConvertFrom-DockerSize $p[0]
                Unique = $p[0]
                Total  = $p[1]
                # An image with a repo but no tag shows as <none>:<none> here and
                # survives `image prune`, so it needs its id to be actionable.
                Name   = if ($p[2] -eq '<none>:<none>') { $p[3] } else { $p[2] }
            }
        } |
        Sort-Object Bytes -Descending |
        ForEach-Object {
            Write-Info ("{0,10}  unique  {1,10}  total   {2}" -f $_.Unique, $_.Total, $_.Name)
        }

    Write-Info ''
    Write-Info 'Cross-check a tag against every image: pin, Dockerfile FROM and'
    Write-Info 'script reference in the sibling checkouts before removing it.'
    return
}

$running = @(docker ps -q)
if ($running.Count -gt 0 -and -not $Force) {
    Write-Fail "$($running.Count) container(s) running -- their images and volumes are in use"
    Write-Info 'stop the stack, or re-run with -Force to prune anyway'
    exit 1
}

$namedBefore = Get-NamedVolumes
Write-Ok "$($namedBefore.Count) named volumes recorded"

# ------------------------------------------------------------------- prune

if (-not $SkipPrune) {
    $anon = @(@(docker volume ls -q -f dangling=true) | Where-Object { $_ -match $AnonPattern })

    # The filter above is the safety boundary, so assert it rather than trust it.
    $leaked = $anon | Where-Object { $_ -notmatch $AnonPattern }
    if ($leaked) { throw "refusing to continue: non-anonymous name in delete list: $($leaked -join ', ')" }

    if ($DryRun) {
        Write-Step 'Prune (dry run)'
        Write-Info "$(@(docker ps -aq).Count) container(s) would be removed"
        Write-Info "$(@(docker images -f dangling=true -q).Count) dangling image(s) would be removed"
        Write-Info "$($anon.Count) orphaned anonymous volume(s) would be removed"
        Write-Info "$($namedBefore.Count) named volume(s) would be kept"
        Write-Info 'build cache: see RECLAIMABLE in the table above'
    } else {
        Write-Step 'Pruning stopped containers'
        docker container prune -f | Select-Object -Last 1 | ForEach-Object { Write-Info $_ }

        Write-Step "Removing $($anon.Count) orphaned anonymous volumes"
        if ($anon.Count -gt 0) {
            # Batched: one docker call per volume is minutes of process spawn on
            # a thousand of them, and the whole argv does not fit in one call.
            for ($i = 0; $i -lt $anon.Count; $i += 100) {
                $last  = [math]::Min($i + 99, $anon.Count - 1)
                $batch = $anon[$i..$last]
                docker volume rm @batch *> $null
            }
            Write-Ok "$($anon.Count) removed"
        } else {
            Write-Ok 'none to remove'
        }

        Write-Step 'Pruning dangling images'
        docker image prune -f | Select-Object -Last 1 | ForEach-Object { Write-Info $_ }

        Write-Step 'Pruning unused build cache'
        docker builder prune -f | Select-Object -Last 1 | ForEach-Object { Write-Info $_ }

        # Named volumes are what this script exists to not touch. Verify, do not assume.
        Write-Step 'Verifying named volumes'
        $namedAfter = Get-NamedVolumes
        $diff = Compare-Object $namedBefore $namedAfter
        if ($diff) {
            Write-Fail 'named volume set CHANGED -- this should be impossible'
            foreach ($d in $diff) {
                $mark = '  lost:  '
                if ($d.SideIndicator -eq '=>') { $mark = '  added: ' }
                Write-Info "$mark$($d.InputObject)"
            }
            exit 1
        }
        Write-Ok "all $($namedAfter.Count) named volumes intact"
    }
}

# -------------------------------------------------------------------- trim

if (-not $SkipTrim) {
    if ($DryRun) {
        Write-Step 'Trim (dry run)'
        Write-Info 'would fstrim /mnt/docker-desktop-disk inside the VM namespace'
    } else {
        Write-Step 'Discarding freed blocks inside the VM'
        docker image inspect alpine:latest *> $null
        if ($LASTEXITCODE -ne 0) {
            Write-Info 'pulling alpine:latest'
            docker pull -q alpine:latest | Out-Null
        }
        # --pid=host plus nsenter into PID 1 puts fstrim in the namespace where
        # the data disk is actually mounted; a plain container cannot see it.
        # busybox has no nsenter, hence util-linux.
        $trim = 'apk add -q --no-cache util-linux >/dev/null 2>&1 && nsenter -t 1 -m -u -i -n fstrim -av'
        $out  = docker run --rm --privileged --pid=host alpine:latest sh -c $trim 2>&1
        if ($LASTEXITCODE -eq 0) {
            $out | ForEach-Object { Write-Info $_ }
            # fstrim reports the free pool it discarded, not what this run freed,
            # so the figure barely moves between runs. It is not a reclaim total.
            Write-Ok 'trimmed (figure is free space discarded, not space reclaimed)'
        } else {
            # Not fatal: compaction still reclaims whatever was already zeroed.
            Write-Warn2 'fstrim failed -- compaction will reclaim less'
            $out | Select-Object -First 3 | ForEach-Object { Write-Info $_ }
        }
    }
}

# ----------------------------------------------------------------- compact

if (-not $SkipCompact -and $null -ne $vhdxBefore) {
    if ($DryRun) {
        Write-Step 'Compact (dry run)'
        Write-Info "would stop Docker Desktop, wsl --shutdown, then Optimize-VHD $VhdxPath"
        Write-Info "vhdx is $vhdxBefore GB"
    } else {
        Write-Step 'Stopping Docker Desktop'
        Stop-Process -Name 'Docker Desktop' -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 4
        Get-Process -Name 'com.docker.backend','com.docker.build','vpnkit','docker' -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3

        Write-Step 'Shutting down WSL'
        wsl.exe --shutdown
        Start-Sleep -Seconds 6
        Write-Ok 'wsl stopped'

        Write-Step 'Compacting the vhdx'
        if (Test-Elevated) {
            Optimize-VHD -Path $VhdxPath -Mode Full
            Write-Ok 'compacted'
        } else {
            # Optimize-VHD needs admin and this script does not, so elevate the
            # single call. A temp script keeps the quoting out of -Command.
            $log   = Join-Path $env:TEMP ("docker-reclaim-{0}.log" -f $PID)
            $inner = Join-Path $env:TEMP ("docker-reclaim-{0}.ps1" -f $PID)
            $lines = @(
                'try {'
                "    Optimize-VHD -Path '$VhdxPath' -Mode Full -ErrorAction Stop"
                "    'OK' | Out-File -FilePath '$log'"
                '} catch {'
                "    ('FAILED: ' + " + '$_.Exception.Message' + ") | Out-File -FilePath '$log'"
                '}'
            )
            Set-Content -Path $inner -Value $lines -Encoding ASCII

            Write-Info 'a UAC prompt will appear'
            Start-Process powershell -Verb RunAs -Wait -ArgumentList @(
                '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $inner)

            $result = 'no result'
            if (Test-Path $log) { $result = (Get-Content $log -Raw).Trim() }
            Remove-Item $inner, $log -ErrorAction SilentlyContinue

            if ($result -eq 'OK') { Write-Ok 'compacted' } else { Write-Warn2 $result }
        }

        Write-Step 'Restarting Docker Desktop'
        Start-Engine
        Write-Ok 'engine up'
    }
}

# ------------------------------------------------------------------ report

Write-Step 'After'
if (-not $DryRun) { docker system df }
$vhdxAfter = Get-VhdxGB
if ($null -ne $vhdxBefore -and $null -ne $vhdxAfter) {
    # The file grows a little on any run that starts a container, so the delta
    # is reported for what it is rather than always as a win.
    $delta = [math]::Round($vhdxBefore - $vhdxAfter, 2)
    if ($delta -gt 0) {
        $note = "$delta GB returned to Windows"
    } elseif ($delta -lt 0) {
        $note = "grew by $([math]::Abs($delta)) GB"
    } else {
        $note = 'unchanged'
    }
    Write-Info ("vhdx {0} GB -> {1} GB  ({2})" -f $vhdxBefore, $vhdxAfter, $note)
}
Write-Info ("C: free {0} GB" -f [math]::Round((Get-PSDrive C).Free / 1GB, 1))
