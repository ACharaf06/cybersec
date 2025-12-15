/*
 * =============================================================================
 * UploadAction.java - File Upload Handler for S2-045 Defense Lab
 * =============================================================================
 * This action handles multipart/form-data uploads and demonstrates:
 * - Secure file upload handling
 * - Comprehensive logging of request metadata
 * - Proper error handling for malformed requests
 * =============================================================================
 */
package com.lab.struts.action;

import com.opensymphony.xwork2.ActionSupport;
import com.opensymphony.xwork2.ActionContext;
import javax.servlet.http.HttpServletRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.util.Enumeration;

/**
 * Handles file upload requests via multipart/form-data.
 * Logs all request metadata for security monitoring.
 */
public class UploadAction extends ActionSupport {

    private static final Logger logger = LogManager.getLogger(UploadAction.class);
    private static final Logger securityLogger = LogManager.getLogger("SECURITY");

    // File upload fields (set by Struts2 file interceptor)
    private File upload;
    private String uploadContentType;
    private String uploadFileName;

    // Request metadata
    private String requestId;
    private String message;

    /**
     * Main action method - processes the file upload request.
     */
    @Override
    public String execute() {
        // Get request from ActionContext
        HttpServletRequest request = (HttpServletRequest) ActionContext.getContext()
                .get(org.apache.struts2.StrutsStatics.HTTP_REQUEST);
        
        // Extract request ID from header (set by nginx)
        requestId = request.getHeader("X-Request-ID");
        if (requestId == null || requestId.isEmpty()) {
            requestId = java.util.UUID.randomUUID().toString().substring(0, 8);
        }

        // Log request metadata for security monitoring
        logRequestMetadata(request);

        try {
            // Check if file was actually uploaded
            if (upload == null) {
                logger.warn("[UPLOAD] Request ID={} - No file uploaded", requestId);
                message = "No file uploaded";
                return INPUT;
            }

            // Log upload details
            logger.info("[UPLOAD] Request ID={} - Processing file: name={}, type={}, size={} bytes",
                    requestId, uploadFileName, uploadContentType, upload.length());

            // Validate file (basic checks)
            if (!isValidUpload()) {
                securityLogger.warn("[SECURITY] Request ID={} - Invalid upload rejected: name={}, type={}",
                        requestId, uploadFileName, uploadContentType);
                message = "Invalid file upload";
                return ERROR;
            }

            // Process successful upload
            message = String.format("File '%s' uploaded successfully (%d bytes)",
                    sanitizeFilename(uploadFileName), upload.length());
            
            logger.info("[UPLOAD] Request ID={} - Upload successful: {}", requestId, message);

            return SUCCESS;

        } catch (Exception e) {
            // Log any parsing/processing errors
            securityLogger.error("[SECURITY] Request ID={} - Upload processing error: {}",
                    requestId, e.getMessage(), e);
            message = "Error processing upload";
            return ERROR;
        }
    }

    /**
     * Logs comprehensive request metadata for security analysis.
     */
    private void logRequestMetadata(HttpServletRequest request) {
        StringBuilder headerLog = new StringBuilder();
        headerLog.append("[REQUEST] ID=").append(requestId);
        headerLog.append(" Method=").append(request.getMethod());
        headerLog.append(" URI=").append(request.getRequestURI());
        headerLog.append(" RemoteAddr=").append(request.getRemoteAddr());

        // Log Content-Type (key header for S2-045 detection)
        String contentType = request.getContentType();
        headerLog.append(" Content-Type=").append(contentType != null ? contentType : "null");

        // Log Content-Length
        headerLog.append(" Content-Length=").append(request.getContentLength());

        logger.info(headerLog.toString());

        // Log all headers (security-relevant for analysis)
        if (logger.isDebugEnabled()) {
            StringBuilder allHeaders = new StringBuilder("[HEADERS] Request ID=").append(requestId);
            Enumeration<String> headerNames = request.getHeaderNames();
            while (headerNames.hasMoreElements()) {
                String name = headerNames.nextElement();
                String value = request.getHeader(name);
                // Truncate long values to prevent log injection
                if (value != null && value.length() > 200) {
                    value = value.substring(0, 200) + "...[TRUNCATED]";
                }
                allHeaders.append(" ").append(name).append("=").append(value);
            }
            logger.debug(allHeaders.toString());
        }

        // Check for suspicious patterns in Content-Type (defense in depth)
        if (contentType != null && isSuspiciousContentType(contentType)) {
            securityLogger.warn("[SECURITY] Request ID={} - Suspicious Content-Type detected: {}",
                    requestId, sanitizeForLog(contentType));
        }
    }

    /**
     * Checks for suspicious patterns in Content-Type header.
     * Defense in depth - nginx WAF should block these, but we check anyway.
     */
    private boolean isSuspiciousContentType(String contentType) {
        String lower = contentType.toLowerCase();
        return lower.contains("${") ||
               lower.contains("%{") ||
               lower.contains("#{") ||
               lower.contains("java.") ||
               lower.contains("runtime") ||
               lower.contains("processbuilder");
    }

    /**
     * Validates the uploaded file.
     */
    private boolean isValidUpload() {
        // Check filename
        if (uploadFileName == null || uploadFileName.isEmpty()) {
            return false;
        }

        // Check for path traversal attempts
        if (uploadFileName.contains("..") || uploadFileName.contains("/") || uploadFileName.contains("\\")) {
            securityLogger.warn("[SECURITY] Request ID={} - Path traversal attempt in filename: {}",
                    requestId, sanitizeForLog(uploadFileName));
            return false;
        }

        // Check file size (max 10MB)
        if (upload.length() > 10 * 1024 * 1024) {
            return false;
        }

        return true;
    }

    /**
     * Sanitizes filename for safe usage.
     */
    private String sanitizeFilename(String filename) {
        if (filename == null) return "unknown";
        return filename.replaceAll("[^a-zA-Z0-9._-]", "_");
    }

    /**
     * Sanitizes string for safe logging (prevents log injection).
     */
    private String sanitizeForLog(String input) {
        if (input == null) return "null";
        // Remove newlines and control characters that could enable log injection
        return input.replaceAll("[\\r\\n\\t]", " ").substring(0, Math.min(input.length(), 200));
    }

    // =========================================================================
    // Setters for Struts2 dependency injection
    // =========================================================================

    public void setUpload(File upload) {
        this.upload = upload;
    }

    public void setUploadContentType(String uploadContentType) {
        this.uploadContentType = uploadContentType;
    }

    public void setUploadFileName(String uploadFileName) {
        this.uploadFileName = uploadFileName;
    }

    // =========================================================================
    // Getters for JSP view
    // =========================================================================

    public String getMessage() {
        return message;
    }

    public String getRequestId() {
        return requestId;
    }

    public String getUploadFileName() {
        return uploadFileName;
    }
}
