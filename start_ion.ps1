# Load .env file into environment
$envFile = Join-Path $PSScriptRoot '.env'
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith('#')) {
            $parts = $line -split '=', 2
            if ($parts.Count -eq 2) {
                $key = $parts[0].Trim()
                $val = $parts[1].Trim()
                [Environment]::SetEnvironmentVariable($key, $val, 'Process')
                Write-Output "  SET $key"
            }
        }
    }
    Write-Output "Loaded .env"
}

# Check if this is a first run (no .seeded marker)
$markerPath = Join-Path $HOME '.ion' '.seeded'
$needsSeed = -not (Test-Path $markerPath)

if ($needsSeed) {
    Write-Output ""
    Write-Output "First run detected — will auto-seed after server starts."
    Write-Output ""

    # Start ION in background
    Write-Output "Starting ION (background)..."
    $serverProc = Start-Process -FilePath 'C:\Python314\Scripts\ion-web.exe' -PassThru -WindowStyle Hidden

    # Wait for health endpoint
    $seedUrl = if ($env:ION_SEED_URL) { $env:ION_SEED_URL } else { "http://127.0.0.1:8000" }
    $healthUrl = "$seedUrl/api/health"
    Write-Output "Waiting for ION at $healthUrl ..."
    $timeout = 60
    $elapsed = 0
    while ($elapsed -lt $timeout) {
        try {
            $resp = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
            if ($resp.StatusCode -eq 200) {
                Write-Output "  ION is healthy."
                break
            }
        } catch {
            # Not ready yet
        }
        Start-Sleep -Seconds 3
        $elapsed += 3
        Write-Output "  Not ready, retrying... ($($timeout - $elapsed)s remaining)"
    }

    if ($elapsed -ge $timeout) {
        Write-Output "ERROR: ION did not start within ${timeout}s. Skipping seed."
    } else {
        # Run seed_all.py
        Write-Output ""
        Write-Output "Running seed_all.py ..."
        # Set ION_DATA_DIR to home dir for local dev (marker goes to ~/.ion/.seeded)
        [Environment]::SetEnvironmentVariable('ION_DATA_DIR', $HOME, 'Process')
        & 'C:\Python314\python.exe' (Join-Path $PSScriptRoot 'seed_all.py')
        Write-Output ""
    }

    # Bring server to foreground — stop background process and restart in foreground
    Write-Output "Restarting ION in foreground..."
    Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    & 'C:\Python314\Scripts\ion-web.exe'
} else {
    Write-Output "Already seeded ($markerPath exists)."
    Write-Output ""
    # Start ION normally
    Write-Output "Starting ION..."
    & 'C:\Python314\Scripts\ion-web.exe'
}
