Set-Location C:\Users\Tomo\ion
foreach ($line in Get-Content .env) {
    if ($line -match '^\s*([^#][^=]+)=(.*)$') {
        $key = $Matches[1].Trim()
        $val = $Matches[2].Trim()
        [System.Environment]::SetEnvironmentVariable($key, $val, 'Process')
    }
}
& C:\Python314\python.exe -m ion.web.server
