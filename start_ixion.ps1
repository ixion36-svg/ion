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

# Start IXION
Write-Output "Starting IXION..."
& 'C:\Python314\Scripts\ixion-web.exe'
