<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="s" uri="/struts-tags" %>
<!DOCTYPE html>
<!--
  =============================================================================
  Index Page - S2-045 Vulnerable Lab
  =============================================================================
-->
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>S2-045 Vulnerable Lab</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #7f1d1d 0%, #991b1b 100%);
            color: #e0e0e0;
            min-height: 100vh;
            padding: 2rem;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
        }
        h1 {
            color: #fca5a5;
            margin-bottom: 0.5rem;
            font-size: 2rem;
        }
        .subtitle {
            color: #888;
            margin-bottom: 2rem;
        }
        .card {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        .card h2 {
            color: #fca5a5;
            margin-bottom: 1rem;
            font-size: 1.2rem;
        }
        .endpoint {
            background: rgba(0,0,0,0.3);
            padding: 0.75rem 1rem;
            border-radius: 4px;
            margin-bottom: 0.5rem;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.9rem;
        }
        .endpoint span {
            color: #4ade80;
            margin-right: 0.5rem;
        }
        a {
            color: #fca5a5;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        .warning {
            background: rgba(239, 68, 68, 0.2);
            border: 2px solid rgba(239, 68, 68, 0.5);
            color: #fca5a5;
            padding: 1rem;
            border-radius: 4px;
            margin-top: 2rem;
        }
        .warning strong {
            display: block;
            margin-bottom: 0.5rem;
            font-size: 1.1rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>&#x26A0; S2-045 Vulnerable Lab</h1>
        <p class="subtitle">Apache Struts2 Vulnerability Demonstration Environment</p>

        <div class="card">
            <h2>Available Endpoints</h2>
            <div class="endpoint">
                <span>GET</span>
                <a href="health">/health</a> - Health check (JSON)
            </div>
            <div class="endpoint">
                <span>GET</span>
                <a href="upload-form">/upload-form</a> - File upload form
            </div>
            <div class="endpoint">
                <span>POST</span>
                /upload - File upload handler (multipart/form-data)
            </div>
        </div>

        <div class="card">
            <h2>Vulnerability Information</h2>
            <ul style="list-style: none;">
                <li>&#x26A0; Struts 2.3.31 (VULNERABLE to S2-045 / CVE-2017-5638)</li>
                <li>&#x26A0; No WAF protection</li>
                <li>&#x26A0; No rate limiting</li>
                <li>&#x26A0; Minimal security logging</li>
            </ul>
        </div>

        <div class="warning">
            <strong>&#x26A0; WARNING: VULNERABLE APPLICATION</strong>
            This application is intentionally vulnerable for educational purposes.
            It uses Struts 2.3.31 which is vulnerable to S2-045 (CVE-2017-5638).
            Do NOT expose to public networks or use in production.
            See EXPLOITATION_GUIDE.md for details on the vulnerability.
        </div>
    </div>
</body>
</html>

