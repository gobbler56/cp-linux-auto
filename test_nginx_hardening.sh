#!/bin/bash
# test_nginx_hardening.sh - Test script for NGINX hardening module
#
# This script validates that the nginx_hardening module is properly structured
# and can be executed without errors (when nginx is installed)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/utils.sh"

log_section "NGINX Hardening Module Test"

# Test 1: Module file exists and is executable
log_info "Test 1: Checking module file..."
if [[ -f "$SCRIPT_DIR/modules/nginx_hardening.sh" ]]; then
    log_success "✓ Module file exists"
else
    log_error "✗ Module file not found"
    exit 1
fi

if [[ -x "$SCRIPT_DIR/modules/nginx_hardening.sh" ]]; then
    log_success "✓ Module is executable"
else
    log_error "✗ Module is not executable"
    exit 1
fi

# Test 2: Module can be sourced without errors
log_info "Test 2: Checking if module can be sourced..."
if source "$SCRIPT_DIR/modules/nginx_hardening.sh" 2>/dev/null; then
    log_success "✓ Module sourced successfully"
else
    log_error "✗ Module failed to source"
    exit 1
fi

# Test 3: Check for required functions
log_info "Test 3: Checking for required functions..."
required_functions=(
    "run_nginx_hardening"
    "check_nginx_installed"
    "validate_nginx_config"
    "disable_server_tokens"
    "configure_nginx_user"
    "configure_buffer_limits"
    "create_security_headers_config"
    "create_ssl_hardening_config"
    "secure_config_permissions"
    "verify_hardening"
)

for func in "${required_functions[@]}"; do
    if declare -f "$func" >/dev/null; then
        log_success "✓ Function exists: $func"
    else
        log_error "✗ Function missing: $func"
        exit 1
    fi
done

# Test 4: Check for configuration constants
log_info "Test 4: Checking configuration constants..."
required_constants=(
    "NGINX_MAIN_CONFIG"
    "NGINX_SECURITY_HEADERS"
    "NGINX_SSL_PARAMS"
    "NGINX_HARDENING_CONFIG"
)

for const in "${required_constants[@]}"; do
    if [[ -v $const ]]; then
        log_success "✓ Constant defined: $const = ${!const}"
    else
        log_error "✗ Constant missing: $const"
        exit 1
    fi
done

# Test 5: Check if NGINX is installed (informational only)
log_info "Test 5: Checking NGINX installation..."
if command_exists nginx; then
    log_success "✓ NGINX is installed"
    nginx -v 2>&1 | head -1

    log_info "Test 5a: Checking if NGINX config exists..."
    if [[ -f "$NGINX_MAIN_CONFIG" ]]; then
        log_success "✓ NGINX main config exists: $NGINX_MAIN_CONFIG"
    else
        log_warn "⚠ NGINX main config not found: $NGINX_MAIN_CONFIG"
    fi
else
    log_warn "⚠ NGINX is not installed (module will handle this gracefully)"
fi

# Test 6: Verify module integration with engine
log_info "Test 6: Checking engine integration..."
if [[ -f "$SCRIPT_DIR/cp-engine.sh" ]]; then
    log_success "✓ cp-engine.sh exists"
    log_info "  To verify module discovery, run: ./cp-engine.sh -l | grep nginx"
else
    log_error "✗ cp-engine.sh not found"
    exit 1
fi

log_section "All Tests Passed"
log_success "NGINX hardening module is properly configured and ready to use"

echo ""
echo "To run the module:"
echo "  sudo ./cp-engine.sh -m nginx_hardening"
echo ""
echo "Note: NGINX must be installed for the module to apply hardening."
echo "Install NGINX with: sudo apt-get install nginx"
echo ""
