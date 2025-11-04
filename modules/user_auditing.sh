#!/bin/bash
# user_auditing.sh - User Auditing Module
# Audits system users against authorized user list from README

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"
source "$SCRIPT_DIR/readme_parser.sh"

# Module: User Auditing
# Category: User Auditing
# Description: Checks for unauthorized users and ensures authorized users exist

run_user_auditing() {
    log_info "Starting User Auditing module..."

    # Ensure README is parsed
    if [[ $README_PARSED -eq 0 ]]; then
        log_warn "README not parsed, parsing now..."
        parse_readme || {
            log_error "Failed to parse README"
            return 1
        }
    fi

    # TODO: Implementation
    # 1. Get list of all system users (UID >= 1000)
    # 2. Compare against authorized users from README
    # 3. Identify unauthorized users
    # 4. Check for terminated users that still have accounts
    # 5. Create missing authorized users
    # 6. Verify admin privileges match README

    log_info "Auditing system users..."

    # Example: List current users
    log_debug "Current system users (UID >= 1000):"
    awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | while read -r user; do
        log_debug "  - $user"
    done

    log_info "Authorized users from README:"
    get_authorized_users | while read -r user; do
        log_info "  - $user"
    done

    log_info "Terminated users from README:"
    get_terminated_users | while read -r user; do
        log_warn "  - $user (should be removed)"
    done

    log_warn "This module needs full implementation"

    return 0
}

export -f run_user_auditing
