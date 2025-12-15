<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="s" uri="/struts-tags" %>
<!DOCTYPE html>
<!--
  =============================================================================
  File Upload Form - S2-045 Defense Lab
  =============================================================================
-->
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Upload - S2-045 Defense Lab</title>
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
            color: #00d4ff;
            margin-bottom: 0.5rem;
        }
        .subtitle {
            color: #888;
            margin-bottom: 2rem;
        }
        .card {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            padding: 2rem;
        }
        .form-group {
            margin-bottom: 1.5rem;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            color: #00d4ff;
        }
        input[type="file"] {
            background: rgba(0,0,0,0.3);
            border: 2px dashed rgba(255,255,255,0.2);
            border-radius: 4px;
            padding: 2rem;
            width: 100%;
            color: #e0e0e0;
            cursor: pointer;
        }
        input[type="file"]:hover {
            border-color: #00d4ff;
        }
        button {
            background: #00d4ff;
            color: #1a1a2e;
            border: none;
            padding: 0.75rem 2rem;
            border-radius: 4px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }
        button:hover {
            background: #00b8e6;
        }
        .back-link {
            display: inline-block;
            margin-top: 1.5rem;
            color: #888;
            text-decoration: none;
        }
        .back-link:hover {
            color: #00d4ff;
        }
        .info {
            background: rgba(0,212,255,0.1);
            border: 1px solid rgba(0,212,255,0.3);
            padding: 1rem;
            border-radius: 4px;
            margin-bottom: 1.5rem;
            font-size: 0.9rem;
        }
        .errors {
            background: rgba(239,68,68,0.1);
            border: 1px solid rgba(239,68,68,0.3);
            color: #ef4444;
            padding: 1rem;
            border-radius: 4px;
            margin-bottom: 1.5rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>&#x1F4C1; File Upload</h1>
        <p class="subtitle">Upload a file to test multipart handling</p>

        <div class="card">
            <div class="info">
                <strong>Allowed files:</strong> .txt, .csv, .pdf, .json, .jpg, .png, .gif<br>
                <strong>Max size:</strong> 10MB
            </div>

            <s:if test="hasActionErrors()">
                <div class="errors">
                    <s:actionerror/>
                </div>
            </s:if>
            <s:if test="hasFieldErrors()">
                <div class="errors">
                    <s:fielderror/>
                </div>
            </s:if>

            <s:form action="upload" method="post" enctype="multipart/form-data">
                <div class="form-group">
                    <label for="upload">Select File:</label>
                    <s:file name="upload" id="upload"/>
                </div>
                <button type="submit">Upload File</button>
            </s:form>

            <a href="<s:url action=''/>" class="back-link">&larr; Back to Home</a>
        </div>
    </div>
</body>
</html>

