#!/bin/bash
# =============================================================================
# S2-045 Attack Pattern Simulator
# =============================================================================
# This script sends test requests that simulate S2-045 attack PATTERNS
# WITHOUT containing any actual exploit payloads or OGNL expressions.
#
# Purpose:
# - Test that WAF rules detect and block suspicious patterns
# - Verify application handles malformed requests safely
# - Generate log entries for security analysis training
#
# IMPORTANT: This script contains NO working exploits.
# =============================================================================

# Configuration
TARGET_HOST="${TARGET_HOST:-nginx}"
TARGET_PORT="${TARGET_PORT:-80}"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}/struts-lab"
DELAY="${DELAY:-1}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TOTAL_TESTS=0
BLOCKED=0
PASSED=0
ERRORS=0

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

log_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE} $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
}

log_test() {
    echo ""
    echo -e "${YELLOW}[TEST $TOTAL_TESTS] $1${NC}"
}

log_result() {
    local status=$1
    local expected=$2
    local response=$3
    
    if [[ "$status" == "$expected" ]] || [[ "$expected" == "any" ]]; then
        echo -e "${GREEN}  ✓ Result: HTTP $status (Expected: $expected)${NC}"
        if [[ "$expected" == "403" ]] || [[ "$expected" == "400" ]]; then
            BLOCKED=$((BLOCKED + 1))
        else
            PASSED=$((PASSED + 1))
        fi
    else
        echo -e "${RED}  ✗ Result: HTTP $status (Expected: $expected)${NC}"
        ERRORS=$((ERRORS + 1))
    fi
    
    if [[ -n "$response" ]]; then
        echo -e "  Response: ${response:0:100}"
    fi
}

wait_for_service() {
    echo "Waiting for service at ${BASE_URL}/health..."
    for i in {1..30}; do
        if curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/health" | grep -q "200"; then
            echo "Service is ready!"
            return 0
        fi
        echo "  Attempt $i/30..."
        sleep 2
    done
    echo "Service not available after 60 seconds"
    exit 1
}

# -----------------------------------------------------------------------------
# Test Cases
# -----------------------------------------------------------------------------

run_tests() {
    log_header "S2-045 DEFENSE LAB - ATTACK PATTERN SIMULATOR"
    echo ""
    echo "Target: ${BASE_URL}"
    echo "NOTE: No actual exploits are sent. Testing detection patterns only."
    echo ""

    wait_for_service

    # =========================================================================
    # BASELINE TESTS - Legitimate Requests
    # =========================================================================
    
    log_header "BASELINE TESTS - Legitimate Requests"

    # Test 1: Health check
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log_test "Health Check Endpoint"
    response=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/health" || echo "000")
    log_result "$response" "200"
    sleep $DELAY

    # Test 2: Index page
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log_test "Index Page"
    response=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/" || echo "000")
    log_result "$response" "200"
    sleep $DELAY

    # Test 3: Upload form (GET)
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log_test "Upload Form (GET)"
    response=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/upload-form" || echo "000")
    log_result "$response" "200"
    sleep $DELAY

    # Test 4: Legitimate file upload
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log_test "Legitimate File Upload"
    echo "This is a test file for the S2-045 defense lab." > /tmp/test.txt || true
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST \
        -F "upload=@/tmp/test.txt" \
        "${BASE_URL}/upload" 2>/dev/null || echo "000")
    log_result "$response" "200"
    rm -f /tmp/test.txt
    sleep $DELAY

    # =========================================================================
    # WAF TESTS - Suspicious Content-Type Patterns
    # =========================================================================
    
    log_header "WAF TESTS - Suspicious Content-Type Patterns"
    echo "These requests contain patterns that LOOK suspicious but contain NO exploits."
    echo "The WAF should block them based on pattern matching."

    # Test 5: Content-Type with expression marker %{
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log_test "Content-Type with %{ pattern (should be BLOCKED)"
    echo "Description: Simulates expression language marker in header"
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST \
        -H "Content-Type: multipart/form-data; test=%{something}" \
        -d "test=data" \
        "${BASE_URL}/upload" 2>/dev/null || echo "000")
    log_result "$response" "403"
    sleep $DELAY

    # Test 6: Content-Type with expression marker ${
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log_test "Content-Type with \${ pattern (should be BLOCKED)"
    echo "Description: Simulates variable expansion marker in header"
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST \
        -H 'Content-Type: multipart/form-data; test=${something}' \
        -d "test=data" \
        "${BASE_URL}/upload" 2>/dev/null || echo "000")
    log_result "$response" "403"
    sleep $DELAY

    # Test 7: Content-Type with Java class reference pattern
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log_test "Content-Type with java. reference (should be BLOCKED)"
    echo "Description: Simulates Java class reference pattern"
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST \
        -H "Content-Type: multipart/form-data; java.lang.String" \
        -d "test=data" \
        "${BASE_URL}/upload" 2>/dev/null || echo "000")
    log_result "$response" "403"
    sleep $DELAY

    # Test 8: Content-Type with Runtime keyword
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log_test "Content-Type with Runtime keyword (should be BLOCKED)"
    echo "Description: Simulates dangerous keyword in header"
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST \
        -H "Content-Type: multipart/form-data; Runtime" \
        -d "test=data" \
        "${BASE_URL}/upload" 2>/dev/null || echo "000")
    log_result "$response" "403"
    sleep $DELAY

    # Test 9: Content-Type with ProcessBuilder keyword
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log_test "Content-Type with ProcessBuilder keyword (should be BLOCKED)"
    echo "Description: Simulates dangerous keyword in header"
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST \
        -H "Content-Type: multipart/form-data; ProcessBuilder" \
        -d "test=data" \
        "${BASE_URL}/upload" 2>/dev/null || echo "000")
    log_result "$response" "403"
    sleep $DELAY

    # Test 10: Content-Type with shell path
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log_test "Content-Type with /bin/bash path (should be BLOCKED)"
    echo "Description: Simulates shell path in header"
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST \
        -H "Content-Type: multipart/form-data; /bin/bash" \
        -d "test=data" \
        "${BASE_URL}/upload" 2>/dev/null || echo "000")
    log_result "$response" "403"
    sleep $DELAY

    # Test 11: Content-Type with null byte
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log_test "Content-Type with encoded null byte (should be BLOCKED)"
    echo "Description: Simulates null byte injection attempt"
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST \
        -H "Content-Type: multipart/form-data%00" \
        -d "test=data" \
        "${BASE_URL}/upload" 2>/dev/null || echo "000")
    log_result "$response" "403"
    sleep $DELAY

    # =========================================================================
    # EDGE CASE TESTS
    # =========================================================================
    
    log_header "EDGE CASE TESTS"

    # Test 12: Missing Content-Type
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log_test "POST without Content-Type header"
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST \
        -d "test=data" \
        "${BASE_URL}/upload")
    # Should be handled gracefully (400 or similar)
    log_result "$response" "any"
    sleep $DELAY

    # Test 13: Very long Content-Type
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log_test "Extremely long Content-Type header"
    long_header=$(printf 'x%.0s' {1..500})
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST \
        -H "Content-Type: multipart/form-data; boundary=${long_header}" \
        -d "test=data" \
        "${BASE_URL}/upload" 2>/dev/null || echo "000")
    # Should be handled gracefully
    log_result "$response" "any"
    sleep $DELAY

    # Test 14: Empty POST body
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log_test "Empty POST body with multipart Content-Type"
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST \
        -H "Content-Type: multipart/form-data; boundary=----test" \
        "${BASE_URL}/upload")
    # Should be handled gracefully
    log_result "$response" "any"
    sleep $DELAY

    # =========================================================================
    # SUMMARY
    # =========================================================================
    
    log_header "TEST SUMMARY"
    echo ""
    echo -e "Total Tests: ${TOTAL_TESTS}"
    echo -e "${GREEN}Legitimate Requests Passed: ${PASSED}${NC}"
    echo -e "${RED}Suspicious Patterns Blocked: ${BLOCKED}${NC}"
    echo -e "${YELLOW}Other/Edge Cases: $((TOTAL_TESTS - PASSED - BLOCKED))${NC}"
    echo ""
    
    if [[ $BLOCKED -ge 5 ]]; then
        echo -e "${GREEN}✓ WAF is functioning correctly - blocking suspicious patterns${NC}"
    else
        echo -e "${YELLOW}⚠ Some suspicious patterns may not be blocked - check WAF rules${NC}"
    fi
    
    if [[ $PASSED -ge 3 ]]; then
        echo -e "${GREEN}✓ Application is accepting legitimate requests${NC}"
    else
        echo -e "${RED}✗ Application may have issues with legitimate requests${NC}"
    fi
    
    echo ""
    echo "Check the following logs for details:"
    echo "  - ./logs/nginx/access.log (all requests)"
    echo "  - ./logs/nginx/error.log (WAF blocks)"
    echo "  - ./logs/app/struts-lab.log (application events)"
    echo "  - ./logs/app/security.log (security events)"
    echo ""
    log_header "SIMULATION COMPLETE"
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

run_tests

