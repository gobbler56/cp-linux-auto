#!/bin/bash
# unwanted_software.sh - Unwanted Software Module
# Identifies and removes unauthorized or dangerous software

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Module: Unwanted Software
# Category: Unwanted Software
# Description: Removes unauthorized applications and potential security risks

run_unwanted_software() {
    log_info "Starting Unwanted Software module..."

    # TODO: Implementation
    # 1. List all installed packages
    # 2. Check for common unwanted software:
    #    - Hacking tools (nmap, nikto, john, hydra, metasploit, etc.)
    #    - P2P software (transmission, deluge, etc.)
    #    - Games (unless allowed by README)
    #    - Remote access tools (vnc, teamviewer unless authorized)
    # 3. Cross-reference with README if it specifies allowed software
    # 4. Generate removal recommendations
    # 5. Optionally remove packages

    log_info "Scanning installed packages..."

    # Common unwanted packages in CyberPatriot
    local unwanted_packages=(
        "john"
        "hydra"
        "nmap"
        "zenmap"
        "wireshark"
        "aircrack-ng"
        "netcat"
        "nc"
        "telnet"
        "freeciv"
        "minetest"
        "0ad"
    )

    log_debug "Checking for common unwanted packages..."
    for pkg in "${unwanted_packages[@]}"; do
        if dpkg -l | grep -q "^ii.*${pkg}"; then
            log_warn "Found potentially unwanted package: $pkg"
        fi
    done

    log_warn "This module needs full implementation"

    return 0
}

export -f run_unwanted_software
