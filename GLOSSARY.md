# Security Glossary

This glossary defines key security terms and concepts used in the S2-045 Defense Lab.

---

## A

### **Action**
In Struts2, an Action is a class that handles HTTP requests. Actions contain business logic and return a result string that determines which view (JSP) to render.

### **Apache Struts2**
A popular open-source web application framework for Java. It follows the Model-View-Controller (MVC) architecture pattern and uses OGNL for expression evaluation.

---

## C

### **CVE (Common Vulnerabilities and Exposures)**
A dictionary of publicly known information security vulnerabilities and exposures. Each CVE entry includes a unique identifier (e.g., CVE-2017-5638), description, and references.

**Example**: CVE-2017-5638 is the identifier for the S2-045 vulnerability.

### **Content-Type Header**
An HTTP header that indicates the media type of the request or response body. For file uploads, it typically contains `multipart/form-data` with a boundary parameter.

**Example**: `Content-Type: multipart/form-data; boundary=----WebKitFormBoundary`

### **Content-Type Injection**
A type of injection attack where malicious content is inserted into the HTTP `Content-Type` header. In S2-045, OGNL expressions are injected into this header to achieve code execution.

---

## D

### **Defense in Depth**
A security strategy that employs multiple layers of defense mechanisms. If one layer fails, others can still protect the system.

**In this lab**: WAF rules, rate limiting, request size limits, and application-level validation.

---

## E

### **Error Handling**
The process of responding to and recovering from error conditions. Insecure error handling can expose sensitive information or create security vulnerabilities (as in S2-045).

---

## F

### **File Upload Interceptor**
A Struts2 interceptor that handles multipart/form-data requests, extracts uploaded files, and makes them available to actions. The interceptor validates file size, type, and extensions.

---

## H

### **HTTP Header**
Key-value pairs sent at the beginning of HTTP requests or responses. Headers provide metadata about the request/response (e.g., Content-Type, Content-Length, User-Agent).

---

## I

### **Input Validation**
The process of checking and sanitizing user input before processing. Proper input validation prevents injection attacks and other security vulnerabilities.

### **Interceptor**
In Struts2, an interceptor is a component that processes requests before they reach actions. Interceptors can perform validation, logging, authentication, and other cross-cutting concerns.

---

## J

### **Jakarta Multipart Parser**
A Java library (formerly Apache Commons FileUpload) used by Struts2 to parse multipart/form-data requests. The parser extracts form fields and file uploads from the request body.

---

## M

### **Multipart/Form-Data**
An encoding type for HTML forms that allows file uploads. The request body is divided into multiple parts, each with its own headers and content.

**Structure**:
```
------boundary
Content-Disposition: form-data; name="field1"

value1
------boundary
Content-Disposition: form-data; name="file"; filename="test.txt"
Content-Type: text/plain

[file content]
------boundary--
```

---

## O

### **OGNL (Object-Graph Navigation Language)**
A powerful expression language used by Struts2 for:
- Accessing object properties
- Invoking methods
- Type conversion
- Expression evaluation

**Security Concern**: OGNL can execute arbitrary Java code, making it dangerous when user input is evaluated without proper restrictions.

**Example**: `${#application}` accesses the application scope.

---

## P

### **Payload**
In security context, a payload is the malicious code or data used to exploit a vulnerability. In S2-045, the payload is an OGNL expression injected into the Content-Type header.

---

## R

### **RCE (Remote Code Execution)**
A security vulnerability that allows an attacker to execute arbitrary code on a remote system. S2-045 is an RCE vulnerability because it enables remote command execution.

**Impact**: Complete system compromise - attackers can:
- Execute system commands
- Access file system
- Install backdoors
- Exfiltrate data
- Pivot to other systems

### **Rate Limiting**
A security mechanism that restricts the number of requests a client can make within a time period. Prevents brute-force attacks and DoS attempts.

**In this lab**: Nginx limits requests to 10 per second per IP.

---

## S

### **S2-045**
The identifier for the Apache Struts2 vulnerability (CVE-2017-5638). The "S2" prefix indicates "Struts2", and "045" is the sequential vulnerability number.

### **Security Logging**
The practice of logging security-relevant events (failed logins, suspicious requests, attacks) for analysis and incident response.

**In this lab**: Security events are logged to `logs/app/security.log`.

### **Servlet**
A Java component that handles HTTP requests and generates responses. Struts2 uses servlet filters to intercept and process requests.

---

## T

### **Tomcat**
An open-source Java servlet container (application server) that implements the Java Servlet and JavaServer Pages (JSP) specifications. In this lab, Tomcat hosts the Struts2 application.

---

## V

### **Vulnerability**
A weakness in a system that can be exploited to cause harm. S2-045 is a vulnerability in Struts2 that allows remote code execution.

### **Vulnerable Version**
A software version containing a known security vulnerability. In this lab, Struts 2.3.31 is the vulnerable version used for demonstration.

---

## W

### **WAF (Web Application Firewall)**
A security solution that monitors, filters, and blocks HTTP traffic to web applications. WAFs can detect and prevent common attacks like SQL injection, XSS, and in this case, OGNL injection.

**In this lab**: Nginx acts as a lightweight WAF with regex-based rules to detect suspicious Content-Type patterns.

### **WAR (Web Application Archive)**
A Java archive file format used to distribute web applications. Contains servlets, JSPs, configuration files, and dependencies.

**In this lab**: The Struts2 application is packaged as a WAR file and deployed to Tomcat.

---

## X

### **XSS (Cross-Site Scripting)**
A vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. Not directly related to S2-045, but another common web application vulnerability.

---

## Additional Terms

### **Boundary**
In multipart/form-data requests, a boundary is a unique string that separates different parts of the request body. It's specified in the Content-Type header.

**Example**: `Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW`

### **Expression Language Injection**
A type of injection attack where malicious expressions are inserted into code that evaluates expressions (like OGNL, EL, SpEL). S2-045 is an OGNL injection vulnerability.

### **Filter Chain**
In Struts2, a sequence of interceptors that process requests in order. Each interceptor can modify the request, perform validation, or block the request.

### **Interceptor Stack**
A predefined sequence of interceptors used by Struts2 actions. The `defaultStack` includes interceptors for validation, file upload, exception handling, etc.

### **OGNL Context**
The execution environment for OGNL expressions, containing variables, objects, and security restrictions. In S2-045, attackers bypass these restrictions to execute arbitrary code.

### **Request ID**
A unique identifier assigned to each HTTP request for tracking and logging purposes. Helps correlate logs across different systems.

**In this lab**: Nginx generates request IDs and passes them to the application via the `X-Request-ID` header.

---

## Security Best Practices Referenced

### **Input Sanitization**
Removing or encoding potentially dangerous characters from user input before processing.

### **Output Encoding**
Encoding data before sending it to clients to prevent injection attacks.

### **Least Privilege**
Granting users and processes only the minimum permissions necessary to perform their functions.

### **Defense in Depth**
Using multiple security controls to protect against threats.

### **Fail Securely**
When errors occur, the system should fail in a secure state (e.g., deny access rather than allow it).

### **Security by Design**
Incorporating security considerations from the initial design phase, not as an afterthought.

---

## Related Vulnerabilities

### **S2-046 (CVE-2017-5638)**
A related vulnerability in Struts2 file upload handling, discovered shortly after S2-045.

### **S2-052 (CVE-2017-12611)**
A deserialization vulnerability in Struts2 REST plugin.

### **S2-057 (CVE-2018-11776)**
A namespace manipulation vulnerability in Struts2.

---

## References

- **OWASP Glossary**: https://owasp.org/www-community/OWASP_Glossary
- **CVE Glossary**: https://cve.mitre.org/about/terminology.html
- **Apache Struts Documentation**: https://struts.apache.org/getting-started/
- **OGNL Documentation**: https://commons.apache.org/proper/commons-ognl/

