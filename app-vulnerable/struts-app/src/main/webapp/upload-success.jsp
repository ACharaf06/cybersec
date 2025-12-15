<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="s" uri="/struts-tags" %>
<!DOCTYPE html>
<!--
  =============================================================================
  Upload Success Page - S2-045 Defense Lab
  =============================================================================
-->
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload Successful - S2-045 Defense Lab</title>
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
            color: #4ade80;
            margin-bottom: 0.5rem;
        }
        .card {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(74,222,128,0.3);
            border-radius: 8px;
            padding: 2rem;
            margin-top: 1.5rem;
        }
        .success-icon {
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
            color: #00d4ff;
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
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="success-icon">&#x2705;</div>
            <h1 style="text-align: center;">Upload Successful</h1>
            
            <div class="details">
                <p><strong>Message:</strong> <s:property value="message"/></p>
                <p><strong>Request ID:</strong> <s:property value="requestId"/></p>
                <p><strong>Filename:</strong> <s:property value="uploadFileName"/></p>
            </div>

            <div style="text-align: center;">
                <a href="<s:url action='upload-form'/>">&larr; Upload Another File</a>
                &nbsp;|&nbsp;
                <a href="<s:url action=''/>">&larr; Back to Home</a>
            </div>
        </div>
    </div>
</body>
</html>

