<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="s" uri="/struts-tags" %>
<!DOCTYPE html>
<!--
  =============================================================================
  Upload Error Page - S2-045 Defense Lab
  =============================================================================
-->
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload Error - S2-045 Defense Lab</title>
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
            max-width: 600px;
            margin: 0 auto;
        }
        h1 {
            color: #ef4444;
            margin-bottom: 0.5rem;
        }
        .card {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(239,68,68,0.3);
            border-radius: 8px;
            padding: 2rem;
            margin-top: 1.5rem;
        }
        .error-icon {
            font-size: 4rem;
            text-align: center;
            margin-bottom: 1rem;
        }
        .details {
            background: rgba(0,0,0,0.3);
            padding: 1rem;
            border-radius: 4px;
            margin-top: 1rem;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.9rem;
        }
        .details p {
            margin-bottom: 0.5rem;
        }
        .details strong {
            color: #ef4444;
        }
        a {
            display: inline-block;
            margin-top: 1.5rem;
            color: #00d4ff;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        .security-note {
            background: rgba(251, 191, 36, 0.1);
            border: 1px solid rgba(251, 191, 36, 0.3);
            color: #fbbf24;
            padding: 1rem;
            border-radius: 4px;
            margin-top: 1rem;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="error-icon">&#x26A0;</div>
            <h1 style="text-align: center;">Upload Failed</h1>
            
            <div class="details">
                <p><strong>Error:</strong> <s:property value="message" default="An error occurred during upload"/></p>
                <p><strong>Request ID:</strong> <s:property value="requestId" default="unknown"/></p>
            </div>

            <s:if test="hasActionErrors()">
                <div class="security-note">
                    <strong>Details:</strong>
                    <s:actionerror/>
                </div>
            </s:if>

            <div class="security-note">
                <strong>&#x1F6E1; Security Note:</strong> This error has been logged for security analysis.
                Check /logs/app/security.log for details.
            </div>

            <div style="text-align: center;">
                <a href="<s:url action='upload-form'/>">&larr; Try Again</a>
                &nbsp;|&nbsp;
                <a href="<s:url action=''/>">&larr; Back to Home</a>
            </div>
        </div>
    </div>
</body>
</html>

