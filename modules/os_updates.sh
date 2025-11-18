#!/bin/bash
# os_updates.sh - Operating System Updates Module
# Manages operating system and kernel updates

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Module: Operating System Updates
# Category: Operating System Updates
# Description: Ensures OS and kernel are up to date, installs and configures automatic updates

# Fix APT sources - assumes broken and fixes without checking
fix_apt_sources() {
    log_section "Fixing APT Sources"

    local os=$(detect_os)
    local version=$(detect_os_version)

    log_info "Detected OS: $os $version"

    # Determine if Ubuntu 24 or Mint 21
    if [[ "$os" == "linuxmint" && "$version" == "21"* ]]; then
        log_info "Configuring APT sources for Linux Mint 21..."

        # Backup existing files
        [[ -f /etc/apt/sources.list.d/official-package-repositories.list ]] && \
            backup_file /etc/apt/sources.list.d/official-package-repositories.list
        [[ -f /etc/apt/sources.list ]] && \
            backup_file /etc/apt/sources.list

        # Write Mint 21 sources to official-package-repositories.list
        log_info "Writing Mint 21 sources to official-package-repositories.list..."
        cat <<'EOF' | tee /etc/apt/sources.list.d/official-package-repositories.list >/dev/null
deb http://packages.linuxmint.com virginia main upstream import backport

deb http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-backports main restricted universe multiverse

deb http://security.ubuntu.com/ubuntu/ jammy-security main restricted universe multiverse
EOF

        # Write Mint 21 sources to sources.list
        log_info "Writing Mint 21 sources to sources.list..."
        cat <<'EOF' | tee /etc/apt/sources.list >/dev/null
deb http://packages.linuxmint.com virginia main upstream import backport

deb http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-backports main restricted universe multiverse

deb http://security.ubuntu.com/ubuntu/ jammy-security main restricted universe multiverse
EOF

        log_success "Linux Mint 21 APT sources configured successfully"

    elif [[ "$os" == "ubuntu" && "$version" == "24."* ]]; then
        log_info "Configuring APT sources for Ubuntu 24..."

        # Backup existing files
        [[ -f /etc/apt/sources.list.d/ubuntu.sources ]] && \
            backup_file /etc/apt/sources.list.d/ubuntu.sources
        [[ -f /etc/apt/sources.list ]] && \
            backup_file /etc/apt/sources.list

        # Get the codename dynamically
        local codename=$(lsb_release -cs)
        log_info "Using Ubuntu codename: $codename"

        # Write Ubuntu sources to ubuntu.sources
        log_info "Writing Ubuntu sources to ubuntu.sources..."
        cat <<EOF | tee /etc/apt/sources.list.d/ubuntu.sources >/dev/null
deb http://archive.ubuntu.com/ubuntu $codename main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu $codename-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu $codename-security main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu $codename-backports main universe restricted multiverse
EOF

        # Write Ubuntu sources to sources.list
        log_info "Writing Ubuntu sources to sources.list..."
        cat <<EOF | tee /etc/apt/sources.list >/dev/null
deb http://archive.ubuntu.com/ubuntu $codename main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu $codename-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu $codename-security main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu $codename-backports main universe restricted multiverse
EOF

        log_success "Ubuntu 24 APT sources configured successfully"

    else
        log_error "Unsupported OS: $os $version"
        log_error "This module only supports Ubuntu 24.x and Linux Mint 21.x"
        return 1
    fi

    return 0
}

# Update package lists
update_package_lists() {
    log_section "Updating Package Lists"

    log_info "Running apt-get update..."
    if apt-get update >/dev/null 2>&1; then
        log_success "Package lists updated successfully"
        return 0
    else
        log_error "Failed to update package lists"
        return 1
    fi
}

# Install unattended-upgrades package
install_unattended_upgrades() {
    log_section "Installing Unattended Upgrades"

    # Check if already installed
    if dpkg -l | grep -q "^ii.*unattended-upgrades"; then
        log_success "unattended-upgrades is already installed"
        return 0
    fi

    log_info "Installing unattended-upgrades package..."
    if apt-get install -y unattended-upgrades >/dev/null 2>&1; then
        log_success "unattended-upgrades installed successfully"
        return 0
    else
        log_error "Failed to install unattended-upgrades"
        return 1
    fi
}

# Configure unattended-upgrades
configure_unattended_upgrades() {
    log_section "Configuring Unattended Upgrades"

    log_info "Configuring unattended-upgrades with dpkg-reconfigure..."
    if dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1; then
        log_success "unattended-upgrades configured successfully"
        return 0
    else
        log_error "Failed to configure unattended-upgrades"
        return 1
    fi
}

# Enable automatic update timers
enable_auto_update_timers() {
    log_section "Enabling Automatic Update Timers"

    # Check if systemd is available
    if ! command_exists systemctl; then
        log_warn "systemctl not found, skipping timer configuration"
        return 0
    fi

    # Enable apt-daily.timer
    log_info "Enabling apt-daily.timer..."
    if systemctl enable apt-daily.timer >/dev/null 2>&1; then
        log_success "apt-daily.timer enabled"
    else
        log_warn "Failed to enable apt-daily.timer"
    fi

    # Start apt-daily.timer
    log_info "Starting apt-daily.timer..."
    systemctl start apt-daily.timer >/dev/null 2>&1

    # Enable apt-daily-upgrade.timer
    log_info "Enabling apt-daily-upgrade.timer..."
    if systemctl enable apt-daily-upgrade.timer >/dev/null 2>&1; then
        log_success "apt-daily-upgrade.timer enabled"
    else
        log_warn "Failed to enable apt-daily-upgrade.timer"
    fi

    # Start apt-daily-upgrade.timer
    log_info "Starting apt-daily-upgrade.timer..."
    systemctl start apt-daily-upgrade.timer >/dev/null 2>&1

    # Verify timers are active
    log_info "Verifying timer status..."
    if systemctl is-active --quiet apt-daily.timer; then
        log_success "apt-daily.timer is active"
    else
        log_warn "apt-daily.timer is not active"
    fi

    if systemctl is-active --quiet apt-daily-upgrade.timer; then
        log_success "apt-daily-upgrade.timer is active"
    else
        log_warn "apt-daily-upgrade.timer is not active"
    fi

    return 0
}

# Perform full system upgrade
perform_full_upgrade() {
    log_section "Performing Full System Upgrade"

    log_info "Current kernel version: $(uname -r)"

    log_info "Running full system upgrade (this may take a while)..."
    log_info "This will upgrade all packages and install new dependencies as needed"

    # Use DEBIAN_FRONTEND to avoid interactive prompts
    export DEBIAN_FRONTEND=noninteractive

    if apt-get -y full-upgrade -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" >/dev/null 2>&1; then
        log_success "Full system upgrade completed successfully"
    else
        log_error "System upgrade encountered errors"
        return 1
    fi

    return 0
}

# Remove unnecessary packages
autoremove_packages() {
    log_section "Removing Unnecessary Packages"

    log_info "Running apt-get autoremove to clean up unused packages..."

    if apt-get -y autoremove --purge >/dev/null 2>&1; then
        log_success "Unnecessary packages removed successfully"
        return 0
    else
        log_error "Failed to remove unnecessary packages"
        return 1
    fi
}

# Check if system reboot is required
check_reboot_required() {
    log_section "Checking Reboot Status"

    if [[ -f /var/run/reboot-required ]]; then
        log_warn "=========================================="
        log_warn "SYSTEM REBOOT REQUIRED/ADVISED"
        log_warn "=========================================="
        log_warn "A system reboot is required to complete updates"

        if [[ -f /var/run/reboot-required.pkgs ]]; then
            log_info "Packages requiring reboot:"
            cat /var/run/reboot-required.pkgs | while read pkg; do
                log_info "  - $pkg"
            done
        fi

        log_warn "Please reboot the system at your earliest convenience"
        log_warn "Run: sudo reboot"
    else
        log_success "No reboot required at this time"
    fi

    return 0
}

# Display update summary
display_update_summary() {
    log_section "Update Summary"

    log_info "Current kernel version: $(uname -r)"
    log_info "System information:"
    log_info "  OS: $(detect_os)"
    log_info "  Version: $(detect_os_version)"

    # Check for available updates
    log_info "Checking for remaining updates..."
    local updates=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst")

    if [[ $updates -eq 0 ]]; then
        log_success "System is fully up to date"
    else
        log_info "There are $updates package(s) that could be updated"
    fi

    return 0
}

run_os_updates() {
    log_info "Starting OS Updates module..."

    log_section "Choose Update Mode"
    log_info "1) Fix APT and configure automatic updates"
    log_info "2) Full run (includes full upgrade) [default]"
    read -r -p "Select update mode [1/2]: " update_choice

    # Default to option 2 (full run) if no choice provided
    if [[ -z "$update_choice" ]]; then
        update_choice=2
    fi

    case "$update_choice" in
        1)
            log_info "Running APT repair and auto-update configuration only"
            ;;
        2)
            log_info "Running full OS update flow"
            ;;
        *)
            log_warn "Unrecognized choice '$update_choice', defaulting to full OS update"
            update_choice=2
            ;;
    esac

    # Fix APT sources first (assume broken)
    if ! fix_apt_sources; then
        log_error "Failed to fix APT sources"
        return 1
    fi

    # Update package lists
    if ! update_package_lists; then
        log_error "Cannot proceed without updated package lists"
        return 1
    fi

    # Install unattended-upgrades
    install_unattended_upgrades

    # Configure automatic updates
    configure_unattended_upgrades

    # Enable systemd timers for automatic updates
    enable_auto_update_timers

    if [[ "$update_choice" == "1" ]]; then
        log_warn "Skipping full system upgrade per user selection"
    else
        # Perform full system upgrade
        perform_full_upgrade

        # Clean up unnecessary packages
        autoremove_packages

        # Check if reboot is needed (after kernel updates)
        check_reboot_required
    fi

    # Display summary
    display_update_summary

    log_success "OS Updates module completed"
    return 0
}

export -f run_os_updates
