<%@ page contentType="text/html;charset=UTF-8" language="java" isErrorPage="true" %>
<%@ taglib prefix="s" uri="/struts-tags" %>
<!DOCTYPE html>
<!--
  =============================================================================
  Error Page - S2-045 Defense Lab
  =============================================================================
-->
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error - S2-045 Defense Lab</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            min-height: 100vh;
            padding: 2rem;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            max-width: 500px;
            text-align: center;
        }
        .error-code {
            font-size: 6rem;
            font-weight: bold;
            color: #ef4444;
            line-height: 1;
        }
        h1 {
            color: #e0e0e0;
            margin: 1rem 0;
        }
        p {
            color: #888;
            margin-bottom: 2rem;
        }
        a {
            display: inline-block;
            background: #00d4ff;
            color: #1a1a2e;
            padding: 0.75rem 2rem;
            border-radius: 4px;
            text-decoration: none;
            font-weight: 600;
        }
        a:hover {
            background: #00b8e6;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="error-code">
            <%= response.getStatus() != 200 ? response.getStatus() : 500 %>
        </div>
        <h1>Something went wrong</h1>
        <p>The request could not be processed. This event has been logged.</p>
        <a href="<%= request.getContextPath() %>/">Return Home</a>
    </div>
</body>
</html>

