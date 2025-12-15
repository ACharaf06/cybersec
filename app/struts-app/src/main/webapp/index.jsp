<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="s" uri="/struts-tags" %>
<!DOCTYPE html>
<!--
  =============================================================================
  Index Page - S2-045 Defense Lab
  =============================================================================
-->
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>S2-045 Defense Lab</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            min-height: 100vh;
            padding: 2rem;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
        }
        h1 {
            color: #00d4ff;
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
            color: #00d4ff;
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
            color: #00d4ff;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        .warning {
            background: rgba(251, 191, 36, 0.1);
            border: 1px solid rgba(251, 191, 36, 0.3);
            color: #fbbf24;
            padding: 1rem;
            border-radius: 4px;
            margin-top: 2rem;
        }
        .warning strong {
            display: block;
            margin-bottom: 0.5rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>&#x1F6E1; S2-045 Defense Lab</h1>
        <p class="subtitle">Apache Struts2 Security Training Environment</p>

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
            <h2>Security Features</h2>
            <ul style="list-style: none;">
                <li>&#x2705; Struts 6.3.x (patched, not vulnerable to S2-045)</li>
                <li>&#x2705; Nginx WAF rules for Content-Type filtering</li>
                <li>&#x2705; Rate limiting (10 req/s)</li>
                <li>&#x2705; Request size limits (10MB)</li>
                <li>&#x2705; Comprehensive security logging</li>
                <li>&#x2705; Localhost-only binding</li>
            </ul>
        </div>

        <div class="warning">
            <strong>⚠️ Educational Environment</strong>
            This is a security training lab. No actual exploits are included.
            See README.md for usage instructions.
        </div>
    </div>
</body>
</html>

