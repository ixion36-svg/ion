$r = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/api/auth/login' -Method POST -ContentType 'application/json' -Body '{"username":"admin","password":"admin2025"}' -UseBasicParsing -SessionVariable s
$r2 = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/api/users' -UseBasicParsing -WebSession $s
$r2.Content
