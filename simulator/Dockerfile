# =============================================================================
# Dockerfile: Attack Pattern Simulator for S2-045 Defense Lab
# =============================================================================
# This container sends test requests that simulate S2-045 attack PATTERNS
# WITHOUT containing any actual exploit payloads.
#
# Purpose:
# - Test WAF rules detect suspicious Content-Type patterns
# - Verify application logs suspicious requests appropriately
# - Confirm defense mechanisms work as expected
#
# IMPORTANT: No actual exploits are included in this simulator.
# =============================================================================

FROM alpine:3.19

LABEL maintainer="Security Lab"
LABEL description="S2-045 Attack Pattern Simulator (NO EXPLOITS)"

# Install curl and bash
RUN apk add --no-cache curl bash coreutils

# Create working directory
WORKDIR /simulator

# Copy simulation script
COPY simulate.sh /simulator/simulate.sh
RUN chmod +x /simulator/simulate.sh

# Run as non-root
RUN adduser -D -s /bin/bash simulator
USER simulator

# Default command
ENTRYPOINT ["/simulator/simulate.sh"]

