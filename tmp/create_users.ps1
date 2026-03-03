# Login as admin
$r = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/api/auth/login' -Method POST -ContentType 'application/json' -Body '{"username":"admin","password":"admin2025"}' -UseBasicParsing -SessionVariable s

# Create analyst1
$body = '{"username":"analyst1","email":"analyst1@localhost","password":"user2025","display_name":"Analyst User","roles":["analyst"]}'
try { Invoke-WebRequest -Uri 'http://127.0.0.1:8000/api/users' -Method POST -ContentType 'application/json' -Body $body -UseBasicParsing -WebSession $s | Select-Object -ExpandProperty Content } catch { $_.Exception.Message }

# Create engineer1
$body = '{"username":"engineer1","email":"engineer1@localhost","password":"user2025","display_name":"Engineer User","roles":["engineering"]}'
try { Invoke-WebRequest -Uri 'http://127.0.0.1:8000/api/users' -Method POST -ContentType 'application/json' -Body $body -UseBasicParsing -WebSession $s | Select-Object -ExpandProperty Content } catch { $_.Exception.Message }

# Create lead1
$body = '{"username":"lead1","email":"lead1@localhost","password":"user2025","display_name":"Lead User","roles":["lead"]}'
try { Invoke-WebRequest -Uri 'http://127.0.0.1:8000/api/users' -Method POST -ContentType 'application/json' -Body $body -UseBasicParsing -WebSession $s | Select-Object -ExpandProperty Content } catch { $_.Exception.Message }

# Create viewer1
$body = '{"username":"viewer1","email":"viewer1@localhost","password":"user2025","display_name":"Viewer User","roles":["viewer"]}'
try { Invoke-WebRequest -Uri 'http://127.0.0.1:8000/api/users' -Method POST -ContentType 'application/json' -Body $body -UseBasicParsing -WebSession $s | Select-Object -ExpandProperty Content } catch { $_.Exception.Message }

# Create editor1
$body = '{"username":"editor1","email":"editor1@localhost","password":"user2025","display_name":"Editor User","roles":["editor"]}'
try { Invoke-WebRequest -Uri 'http://127.0.0.1:8000/api/users' -Method POST -ContentType 'application/json' -Body $body -UseBasicParsing -WebSession $s | Select-Object -ExpandProperty Content } catch { $_.Exception.Message }

Write-Host "`nDone. Verifying users..."
$r2 = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/api/users' -UseBasicParsing -WebSession $s
$r2.Content
