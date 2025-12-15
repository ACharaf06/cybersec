/*
 * =============================================================================
 * UploadAction.java - Vulnerable File Upload Handler
 * =============================================================================
 * WARNING: This action is intentionally vulnerable to S2-045 for educational
 * purposes. It lacks security checks and proper error handling.
 * 
 * This demonstrates the vulnerable code pattern that allows OGNL injection
 * through malformed Content-Type headers in multipart requests.
 * =============================================================================
 */
package com.lab.struts.action;

import com.opensymphony.xwork2.ActionSupport;
import org.apache.struts2.interceptor.ServletRequestAware;
import javax.servlet.http.HttpServletRequest;
import org.apache.log4j.Logger;

import java.io.File;

/**
 * Vulnerable file upload handler - demonstrates S2-045 vulnerability.
 * This version lacks proper security checks and error handling.
 */
public class UploadAction extends ActionSupport implements ServletRequestAware {

    private static final Logger logger = Logger.getLogger(UploadAction.class);

    private HttpServletRequest request;
    
    // File upload fields (set by Struts2 file interceptor)
    private File upload;
    private String uploadContentType;
    private String uploadFileName;
    private String message;

    /**
     * Main action method - processes the file upload request.
     * VULNERABLE: No validation, no security checks, minimal error handling.
     */
    @Override
    public String execute() {
        try {
            // Minimal logging - no security monitoring
            logger.info("Processing upload request");
            
            // Check if file was uploaded
            if (upload == null) {
                message = "No file uploaded";
                return INPUT;
            }

            // Basic processing - no validation
            message = String.format("File '%s' uploaded successfully (%d bytes)",
                    uploadFileName, upload.length());
            
            logger.info("Upload successful: " + message);

            return SUCCESS;

        } catch (Exception e) {
            // VULNERABLE: Exception handling that may expose OGNL evaluation
            // In Struts 2.3.31, error messages containing OGNL expressions
            // in Content-Type headers can be evaluated, leading to RCE
            logger.error("Error processing upload: " + e.getMessage(), e);
            message = "Error processing upload: " + e.getMessage();
            return ERROR;
        }
    }

    // =========================================================================
    // ServletRequestAware implementation
    // =========================================================================
    @Override
    public void setServletRequest(HttpServletRequest request) {
        this.request = request;
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

    public String getUploadFileName() {
        return uploadFileName;
    }
}

