/*
 * =============================================================================
 * HealthAction.java - Health Check Endpoint (Vulnerable Version)
 * =============================================================================
 * Simple health check endpoint for the vulnerable application.
 * =============================================================================
 */
package com.lab.struts.action;

import com.opensymphony.xwork2.ActionSupport;
import org.apache.struts2.interceptor.ServletRequestAware;
import javax.servlet.http.HttpServletRequest;
import org.apache.log4j.Logger;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Health check action providing application status information.
 */
public class HealthAction extends ActionSupport implements ServletRequestAware {

    private static final Logger logger = Logger.getLogger(HealthAction.class);

    private HttpServletRequest request;

    private String status;
    private String timestamp;
    private String uptime;
    private String memory;
    private String strutsVersion;
    private String requestId;

    /**
     * Returns health status of the application.
     */
    @Override
    public String execute() {
        requestId = request != null ? request.getHeader("X-Request-ID") : null;
        if (requestId == null) {
            requestId = "local";
        }

        // Set health status
        status = "healthy";
        timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

        // Calculate uptime
        long uptimeMs = ManagementFactory.getRuntimeMXBean().getUptime();
        long uptimeSeconds = uptimeMs / 1000;
        long hours = uptimeSeconds / 3600;
        long minutes = (uptimeSeconds % 3600) / 60;
        long seconds = uptimeSeconds % 60;
        uptime = String.format("%dh %dm %ds", hours, minutes, seconds);

        // Memory usage
        MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
        long usedHeap = memoryBean.getHeapMemoryUsage().getUsed() / (1024 * 1024);
        long maxHeap = memoryBean.getHeapMemoryUsage().getMax() / (1024 * 1024);
        memory = String.format("%dMB / %dMB", usedHeap, maxHeap);

        // Struts version - vulnerable version
        strutsVersion = "2.3.31 (VULNERABLE to S2-045)";

        logger.debug("Health check - Status: " + status + " Uptime: " + uptime);

        return SUCCESS;
    }

    // =========================================================================
    // ServletRequestAware implementation
    // =========================================================================
    @Override
    public void setServletRequest(HttpServletRequest request) {
        this.request = request;
    }

    // =========================================================================
    // Getters for JSON/JSP view
    // =========================================================================

    public String getStatus() {
        return status;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getUptime() {
        return uptime;
    }

    public String getMemory() {
        return memory;
    }

    public String getStrutsVersion() {
        return strutsVersion;
    }

    public String getRequestId() {
        return requestId;
    }
}

