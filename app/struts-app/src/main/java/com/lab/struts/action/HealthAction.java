/*
 * =============================================================================
 * HealthAction.java - Health Check Endpoint for S2-045 Defense Lab
 * =============================================================================
 * Simple health check endpoint that returns application status.
 * Used by Docker healthcheck and nginx for upstream availability.
 * =============================================================================
 */
package com.lab.struts.action;

import com.opensymphony.xwork2.ActionSupport;
import com.opensymphony.xwork2.ActionContext;
import javax.servlet.http.HttpServletRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.time.Instant;

/**
 * Health check action providing application status information.
 */
public class HealthAction extends ActionSupport {

    private static final Logger logger = LogManager.getLogger(HealthAction.class);

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
        // Get request from ActionContext
        HttpServletRequest request = (HttpServletRequest) ActionContext.getContext()
                .get(org.apache.struts2.StrutsStatics.HTTP_REQUEST);
        requestId = request != null ? request.getHeader("X-Request-ID") : null;
        if (requestId == null) {
            requestId = "local";
        }

        // Set health status
        status = "healthy";
        timestamp = Instant.now().toString();

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

        // Struts version - hardcoded since we know what we're using
        strutsVersion = "6.3.0.2 (patched - not vulnerable to S2-045)";

        // Log health check (at debug level to avoid log spam)
        logger.debug("[HEALTH] Request ID={} - Status: {} Uptime: {} Memory: {}",
                requestId, status, uptime, memory);

        return SUCCESS;
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
