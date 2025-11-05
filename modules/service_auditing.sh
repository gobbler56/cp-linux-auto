#!/bin/bash
# service_auditing.sh - Service Auditing Module
# Audits running services and manages critical/unnecessary services

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"
source "$SCRIPT_DIR/readme_parser.sh"

# Module: Service Auditing
# Category: Service Auditing
# Description: Ensures critical services are running and unnecessary services are stopped

run_service_auditing() {
    log_info "Starting Service Auditing module..."

    log_info "Listing active services..."
    systemctl list-units --type=service --state=running --no-pager --no-legend | \
        awk '{print $1}' | while read service; do
        log_debug "  - $service"
    done

    if [[ $README_PARSED -eq 1 ]]; then
        log_info "Checking critical services from README..."
        get_critical_services | while read service; do
            if systemctl is-active --quiet "$service"; then
                log_success "Critical service running: $service"
            else
                log_error "Critical service NOT running: $service"
            fi
        done
    fi

    log_warn "This module needs full implementation"

    return 0
}

export -f run_service_auditing
