# ION Cyber Range

Hands-on training lab that runs alongside ION. Vulnerable targets + attack tools in Docker containers.

## Quick Start

```bash
# Start the main ION stack first
docker compose up -d

# Then start the range
docker compose -f docker-compose.yml -f docker-compose.range.yml up -d

# Wait for kali tools to install (~2-3 minutes first time)
docker logs -f ion-range-kali
```

## Access Points

| Service | URL / Port | Description |
|---------|-----------|-------------|
| **Kali Terminal** | http://localhost:7681 | Browser-based shell with nmap, sqlmap, hydra, etc. |
| **DVWA** | http://localhost:8081 | Damn Vulnerable Web App (admin/password) |
| **Juice Shop** | http://localhost:3000 | OWASP Juice Shop |
| **WebGoat** | http://localhost:8082 | OWASP WebGoat |
| **Vulnerable SSH** | `ssh root@localhost -p 2222` | Weak creds: root/toor |
| **Vulnerable SMB** | `smbclient //localhost/confidential -p 4455` | Open share (admin/password123) |
| **Vulnerable FTP** | `ftp localhost 2121` | admin/admin123 |
| **ION** | http://localhost:8000 | See alerts from your range activity |

## Network Layout

```
Range Network: 10.30.0.0/24
├── 10.30.0.2   kali           (attack box — your terminal)
├── 10.30.0.10  dvwa           (vulnerable web app)
├── 10.30.0.11  juiceshop      (OWASP Juice Shop)
├── 10.30.0.12  webgoat        (OWASP WebGoat)
├── 10.30.0.20  vuln-ssh       (weak SSH server)
├── 10.30.0.21  vuln-smb       (open SMB share with fake sensitive data)
├── 10.30.0.22  vuln-ftp       (anonymous FTP)
└── 10.30.0.50  range-filebeat (ships logs to Elasticsearch → ION)
```

## Training Exercises

### Exercise 1: Network Discovery
From the Kali terminal:
```bash
nmap -sV 10.30.0.0/24
```
Then check ION's alerts page for any scan detection alerts.

### Exercise 2: Web Application Testing
```bash
# SQL injection on DVWA
sqlmap -u "http://dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=xxx;security=low"

# Directory enumeration on Juice Shop
gobuster dir -u http://juiceshop:3000 -w /usr/share/wordlists/dirb/common.txt
```

### Exercise 3: Credential Attacks
```bash
# SSH brute force
hydra -l root -P /usr/share/wordlists/rockyou.txt vuln-ssh ssh

# SMB enumeration
enum4linux -a vuln-smb
crackmapexec smb vuln-smb -u admin -p password123 --shares
```

### Exercise 4: Data Discovery
```bash
# Access the "confidential" share
smbclient //vuln-smb/confidential -U admin%password123
# Find: Finance reports, HR data, IT credentials

# Check FTP
ftp vuln-ftp 21
# Login: admin / admin123
```

## Logs → ION

Filebeat ships container logs to your Elasticsearch instance. Configure these in your `.env`:
```bash
ION_ELASTICSEARCH_URL=http://your-es:9200
ION_ELASTICSEARCH_USERNAME=elastic
ION_ELASTICSEARCH_PASSWORD=your-password
```

Range activity will appear in ION's:
- Alerts page (if detection rules match)
- Discover page (raw log search)
- Entity Timeline (search by range IPs)

## Shutdown

```bash
# Stop range only (keep ION running)
docker compose -f docker-compose.yml -f docker-compose.range.yml stop kali dvwa juiceshop webgoat vuln-ssh vuln-smb vuln-ftp range-filebeat

# Stop everything including ION
docker compose -f docker-compose.yml -f docker-compose.range.yml down

# Full cleanup (delete range data)
docker compose -f docker-compose.yml -f docker-compose.range.yml down -v
```

## Resource Requirements

| Component | CPU | Memory |
|-----------|-----|--------|
| Kali (tools) | 1-2 cores | 1-2GB |
| DVWA | 0.25 core | 256MB |
| Juice Shop | 0.5 core | 256MB |
| WebGoat | 0.5 core | 512MB |
| Vuln services | 0.25 core | 128MB each |
| Filebeat | 0.25 core | 128MB |
| **Total range** | **~3-4 cores** | **~3-4GB** |

Add to ION's requirements (2 cores, 1.5GB) = **~5-6 cores, 5-6GB total**.
