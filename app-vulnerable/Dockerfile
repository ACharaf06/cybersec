# =============================================================================
# Dockerfile: Vulnerable Struts2 Application on Tomcat 9
# =============================================================================
# This builds a minimal Struts2 webapp using a VULNERABLE version (2.3.31)
# that IS vulnerable to S2-045 (CVE-2017-5638).
#
# WARNING: This container is intentionally vulnerable for educational purposes.
# Do NOT expose to public networks or use in production.
#
# Build stages:
# 1. Maven build stage - compiles the Struts2 application
# 2. Runtime stage - Tomcat 9 with the built WAR file
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build the Vulnerable Struts2 Application
# -----------------------------------------------------------------------------
FROM maven:3.9-eclipse-temurin-17 AS builder

WORKDIR /build

# Copy Maven project files
COPY struts-app/pom.xml ./pom.xml

# Copy source code
COPY struts-app/src ./src

# Build the WAR file
RUN mvn clean package -DskipTests -B

# Verify the WAR was created
RUN ls -la target/*.war

# -----------------------------------------------------------------------------
# Stage 2: Runtime - Tomcat 9 with Vulnerable Struts Application
# -----------------------------------------------------------------------------
FROM tomcat:9.0-jdk17-temurin-jammy

LABEL maintainer="Security Lab"
LABEL description="Struts2 Vulnerable Lab - VULNERABLE version (S2-045)"
LABEL version="1.0"
LABEL security.warning="This container is intentionally vulnerable"

# Remove default webapps for security
RUN rm -rf /usr/local/tomcat/webapps/*

# Create log directories
RUN mkdir -p /usr/local/tomcat/logs/app && \
    chmod 755 /usr/local/tomcat/logs/app

# Copy the built WAR from builder stage
COPY --from=builder /build/target/struts-lab-vulnerable.war /usr/local/tomcat/webapps/struts-lab.war

# Install curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Configure Tomcat logging
RUN echo "handlers = java.util.logging.ConsoleHandler" > /usr/local/tomcat/conf/logging.properties && \
    echo "java.util.logging.ConsoleHandler.level = INFO" >> /usr/local/tomcat/conf/logging.properties && \
    echo "java.util.logging.ConsoleHandler.formatter = java.util.logging.SimpleFormatter" >> /usr/local/tomcat/conf/logging.properties

# Security: Run as non-root user
RUN groupadd -r tomcat && useradd -r -g tomcat tomcat && \
    chown -R tomcat:tomcat /usr/local/tomcat

USER tomcat

# Expose internal port (not bound to host directly)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/struts-lab/health || exit 1

# Start Tomcat
CMD ["catalina.sh", "run"]

