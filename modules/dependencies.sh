#!/bin/bash
# dependencies.sh - Dependencies Module
# Installs required system dependencies for security tools

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Module: Dependencies
# Category: Dependencies
# Description: Installs required system dependencies and security tools

run_dependencies() {
    log_info "Starting Dependencies module..."

    log_info "Checking and installing required dependencies..."

    # Install debsums for package verification
    if ! command_exists debsums; then
        log_info "Installing debsums..."
        if apt-get update -qq && apt-get install -y debsums; then
            log_success "debsums installed successfully"
        else
            log_error "Failed to install debsums"
            return 1
        fi
    else
        log_success "debsums already installed"
    fi

    return 0
}

export -f run_dependencies
