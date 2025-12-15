# Apache Struts2 S2-045 Defense & Exploitation Lab

A Docker-based security lab demonstrating both **exploitation** and **defense** against the Apache Struts2 S2-045 vulnerability (CVE-2017-5638). This lab includes:

1. **Vulnerable Application**: Struts 2.3.31 (vulnerable to S2-045) for exploitation demonstration
2. **Defense Lab**: Struts 6.3.x (patched) with WAF protection for defensive training

> ⚠️ **Security Warning**: This lab contains **working exploits** and **vulnerable code**. Use only in isolated environments. Do NOT expose to public networks.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Host (127.0.0.1 only)                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────┐    ┌─────────────────┐              │
│  │   Simulator     │───▶│  Nginx Proxy    │              │
│  │  (curl-based)   │    │  + WAF Rules    │              │
│  └─────────────────┘    └────────┬────────┘              │
│                                  │                        │
│                          ┌───────┴────────┐              │
│                          │                │                │
│                  ┌───────▼──────┐ ┌───────▼──────┐        │
│                  │  Defense App │ │ Vulnerable   │        │
│                  │ (Struts 6.3) │ │ App (2.3.31) │        │
│                  │ Port: 8080  │ │ Port: 8081  │        │
│                  └──────────────┘ └──────────────┘        │
│                                                             │
│  ┌─────────────────┐                                      │
│  │  Exploit        │───▶ Vulnerable App (8081)            │
│  │  Container      │                                      │
│  └─────────────────┘                                      │
│                                                             │
│  Logs mounted to: ./logs/nginx/, ./logs/app/,             │
│                   ./logs/app-vulnerable/                  │
└─────────────────────────────────────────────────────────────┘
```

## Components

| Container | Purpose | Port |
|-----------|---------|------|
| `nginx` | Reverse proxy with WAF rules, rate limiting | 127.0.0.1:8080 |
| `app` | Tomcat 9 + Struts 6.3.x (patched, defense lab) | Internal only |
| `app-vulnerable` | Tomcat 9 + Struts 2.3.31 (vulnerable, for exploitation) | 127.0.0.1:8081 |
| `exploit` | Exploitation demonstration container | N/A |
| `simulator` | Sends test requests (benign + suspicious patterns) | N/A |

## Getting Started

### Prerequisites

- **Docker** (version 20.10 or later)
- **Docker Compose** (version 2.0 or later)
- **Python 3** (optional, for running exploit scripts directly)
- **curl** (optional, for manual testing)

### Installation

#### 1. Clone the Repository

```bash
# Clone the repository
git clone https://github.com/ACharaf06/cybersec.git
cd cybersec
```

#### 2. Build and Run

```bash
# Build all containers (this may take several minutes on first run)
docker compose build

# Start the defense lab (nginx + patched app)
docker compose up -d nginx app

# Start the vulnerable app (for exploitation demo)
docker compose up -d app-vulnerable

# Verify services are running
docker compose ps

# Wait for services to be healthy (about 60 seconds)
sleep 60

# Check health endpoints
curl http://127.0.0.1:8080/struts-lab/health  # Defense lab
curl http://127.0.0.1:8081/struts-lab/health   # Vulnerable app
```

**Expected Output:**
- Defense lab: JSON response with `"status":"healthy"` and `"strutsVersion":"6.3.0.2 (patched - not vulnerable to S2-045)"`
- Vulnerable app: JSON response with `"status":"healthy"` and `"strutsVersion":"2.3.31 (VULNERABLE to S2-045)"`

### 2. Defense Lab Testing

```bash
# Run the simulator container (tests defense mechanisms)
docker-compose run --rm simulator

# Or run individual tests manually:
# Legitimate upload
curl -X POST -F "file=@README.md" http://127.0.0.1:8080/struts-lab/upload

# Suspicious Content-Type (will be blocked by WAF)
curl -v -X POST \
  -H "Content-Type: multipart/form-data; boundary=----SUSPICIOUS" \
  http://127.0.0.1:8080/struts-lab/upload
```

### 3. Exploitation Demonstration

```bash
# Run the exploit container (demonstrates S2-045 exploitation)
docker-compose --profile exploit run --rm exploit

# Or use the Python exploit script directly
python3 exploit/exploit.py http://127.0.0.1:8081/struts-lab 'whoami'

# Or use the bash script
./exploit/demo_exploit.sh
```

**⚠️ Warning**: The vulnerable application is intentionally exploitable. Only run in isolated environments.

### 4. Observe Logs

```bash
# Defense lab logs
tail -f logs/nginx/access.log      # Nginx access logs
tail -f logs/nginx/error.log       # WAF blocks
tail -f logs/app/struts-lab.log    # Defense app logs

# Vulnerable app logs
tail -f logs/app-vulnerable/struts-lab.log  # Vulnerable app logs

# All logs combined
docker-compose logs -f
```

## What to Observe

### Defense Lab (Port 8080)

**Legitimate Request:**
- Nginx access log: `200` response
- App log: `INFO` level upload processing message
- Request completes successfully

**Suspicious/Malformed Request:**
- Nginx access log: `403 Forbidden` or `400 Bad Request`
- Nginx error log: WAF rule triggered message
- App log: May show parsing error if request reaches app
- Request is blocked or sanitized

### Vulnerable App (Port 8081)

**Successful Exploitation:**
- HTTP 200 or 500 response
- Command output visible in response body
- OGNL expressions evaluated
- System commands executed

**Log Examples:**

**Nginx blocking suspicious Content-Type (Defense Lab):**
```
[WAF] Blocked suspicious Content-Type pattern - Request ID: abc123
```

**App logging request metadata (Defense Lab):**
```
[REQUEST] ID=abc123 Content-Type=multipart/form-data Method=POST URI=/upload
[UPLOAD] Processing file upload for request abc123
```

**Successful exploitation (Vulnerable App):**
```
HTTP/1.1 200 OK
...
root
(Command output appears in response body)
```

## Comparison: Vulnerable vs Defense

| Feature | Vulnerable App (Port 8081) | Defense Lab (Port 8080) |
|---------|---------------------------|-------------------------|
| **Struts Version** | 2.3.31 (vulnerable) | 6.3.0.2 (patched) |
| **WAF Protection** | ❌ None | ✅ Nginx WAF rules |
| **Rate Limiting** | ❌ None | ✅ 10 req/s |
| **Request Size Limits** | ❌ None | ✅ 10MB body, 8KB headers |
| **Security Logging** | ⚠️ Minimal | ✅ Comprehensive |
| **OGNL Injection** | ✅ Exploitable | ❌ Blocked/Patched |
| **RCE Possible** | ✅ Yes | ❌ No |
| **Use Case** | Exploitation demo | Defense training |

## Security Notes

### Isolation
- All services bound to `127.0.0.1` only (no external access)
- Internal Docker network for container communication
- No port exposure to 0.0.0.0
- **Vulnerable app should NEVER be exposed to public networks**

### Defense Layers (Defense Lab)
1. **Nginx WAF Rules**: Block suspicious Content-Type patterns before reaching app
2. **Rate Limiting**: 10 requests/second per IP
3. **Request Size Limits**: 10MB max body, 8KB max headers
4. **Patched Struts**: Uses Struts 6.3.x (not vulnerable to S2-045)
5. **Comprehensive Logging**: All suspicious activity is logged

### What S2-045 Was
S2-045 (CVE-2017-5638) was a critical vulnerability in Apache Struts2 versions 2.3.5 - 2.3.31 and 2.5 - 2.5.10 where:
- Malicious Content-Type headers could inject OGNL expressions
- The Jakarta Multipart parser evaluated these expressions
- This led to Remote Code Execution (RCE)

**The vulnerable app (port 8081) demonstrates this vulnerability.**
**The defense lab (port 8080) shows how to protect against it.**

## File Structure

```
.
├── docker-compose.yml          # Container orchestration
├── README.md                   # This file
├── EXPLOITATION_GUIDE.md      # Detailed exploitation guide
├── TECHNICAL_DETAILS.md        # Technical implementation details
├── GLOSSARY.md                 # Security terms glossary
├── nginx/
│   ├── nginx.conf              # Main nginx configuration
│   └── waf-rules.conf          # WAF rules for S2-045 patterns
├── app/                        # Defense lab (patched)
│   ├── Dockerfile              # Tomcat + Maven build
│   └── struts-app/
│       ├── pom.xml             # Maven project (Struts 6.3.x)
│       └── src/main/
│           ├── java/           # Action classes
│           ├── resources/      # Struts + Log4j config
│           └── webapp/         # JSP views + web.xml
├── app-vulnerable/             # Vulnerable app (for exploitation)
│   ├── Dockerfile              # Tomcat + Maven build
│   └── struts-app/
│       ├── pom.xml             # Maven project (Struts 2.3.31)
│       └── src/main/
│           ├── java/           # Action classes
│           ├── resources/      # Struts + Log4j config
│           └── webapp/         # JSP views + web.xml
├── exploit/                    # Exploitation tools
│   ├── Dockerfile              # Exploit container
│   ├── demo_exploit.sh         # Bash exploit script
│   └── exploit.py              # Python exploit script
├── simulator/
│   ├── Dockerfile              # Alpine + curl
│   └── simulate.sh             # Test script
└── logs/                       # Mounted log directory
    ├── nginx/
    ├── app/                    # Defense lab logs
    └── app-vulnerable/         # Vulnerable app logs
```

## Cleanup

```bash
# Stop all containers
docker compose down

# Remove volumes and logs
docker compose down -v
rm -rf logs/

# Full cleanup (including images)
docker compose down --rmi all -v
```

## Development Setup

### Project Structure

The project is organized as follows:

- `app/` - Defense lab application (Struts 6.3.x, patched)
- `app-vulnerable/` - Vulnerable application (Struts 2.3.31)
- `exploit/` - Exploitation tools and scripts
- `nginx/` - Nginx reverse proxy configuration with WAF rules
- `simulator/` - Attack pattern simulator
- `logs/` - Application logs (gitignored)

### Building Individual Components

```bash
# Rebuild only the vulnerable app
docker compose build app-vulnerable
docker compose up -d app-vulnerable

# Rebuild only the defense app
docker compose build app
docker compose up -d app

# Rebuild exploit container
docker compose build exploit
```

## Documentation

- **[EXPLOITATION_GUIDE.md](EXPLOITATION_GUIDE.md)**: Detailed guide on S2-045 vulnerability mechanism and exploitation procedure
- **[TECHNICAL_DETAILS.md](TECHNICAL_DETAILS.md)**: Technical implementation details of the lab
- **[GLOSSARY.md](GLOSSARY.md)**: Glossary of security terms used in this lab

## Educational Resources

- [Apache Struts Security Bulletins](https://struts.apache.org/security/)
- [CVE-2017-5638 Details](https://nvd.nist.gov/vuln/detail/CVE-2017-5638)
- [OWASP Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
- [Metasploit S2-045 Module](https://www.rapid7.com/db/modules/exploit/multi/http/struts2_content_type_ognl)

---

## ⚠️ Important Warnings

1. **Vulnerable Application**: The app on port 8081 is intentionally vulnerable. Do NOT expose to public networks.
2. **Working Exploits**: This lab contains working exploit code. Use only in isolated environments.
3. **Educational Purpose**: This lab is for security education, research, and authorized penetration testing only.
4. **Legal Compliance**: Only use on systems you own or have explicit written authorization to test.

**Disclaimer**: This lab is for educational purposes only. Use responsibly and only in controlled environments.

