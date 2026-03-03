# Login first
$body = '{"username":"admin","password":"admin2025"}'
try {
    $loginResp = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/api/auth/login' -Method POST -ContentType 'application/json' -Body $body -SessionVariable session
    Write-Host "Login OK"
} catch {
    Write-Host "Login failed: $_"
    exit 1
}

Write-Host "=== Running Health Checks ==="
try {
    $hc = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/integrations/healthcheck' -Method POST -WebSession $session
    $hc | ForEach-Object {
        Write-Host "$($_.integration_type): status=$($_.status)"
        $metaJson = $_.metadata | ConvertTo-Json -Depth 5 -Compress
        Write-Host "  metadata=$metaJson"
    }
} catch {
    Write-Host "HC Error: $_"
}

Write-Host ""
Write-Host "=== Getting Status ==="
try {
    $status = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/integrations/status' -WebSession $session
    $status | ForEach-Object {
        Write-Host "$($_.type): status=$($_.status)"
        $metaJson = $_.metadata | ConvertTo-Json -Depth 5 -Compress
        Write-Host "  metadata=$metaJson"
    }
} catch {
    Write-Host "Status Error: $_"
}
