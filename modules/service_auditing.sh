#!/bin/bash
# service_auditing.sh - Service Auditing Module
# Audits running services and manages critical/unnecessary services

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"
source "$SCRIPT_DIR/../lib/openrouter.sh"
source "$SCRIPT_DIR/readme_parser.sh"

# Module: Service Auditing
# Category: Service Auditing
# Description: Ensures critical services are running and unnecessary services are stopped

# Services that should ALWAYS be enabled/started (regardless of README)
readonly ALWAYS_START_SERVICES=(
    "apparmor"
    "auditd"
    "ufw"
)

# Packages to install if missing
readonly REQUIRED_PACKAGES=(
    "apparmor"
    "apparmor-utils"
    "auditd"
    "ufw"
)

# Services that should ALWAYS be stopped/disabled (regardless of README)
# Note: FTP and web servers removed - they will be handled dynamically based on README
readonly ALWAYS_STOP_SERVICES=(
    "cups"
    "cups-browsed"
    # Torrent clients
    "deluged"
    "deluge-web"
    "transmission-daemon"
    "qbittorrent"
    "rtorrent"
    "ktorrent"
    # Telnet
    "telnetd"
    "inetd"
    "xinetd"
)

# System prompt for AI service analysis
readonly SERVICE_ANALYSIS_PROMPT='You are a security specialist analyzing running services on a CyberPatriot competition system.

Your task is to determine which services should be STOPPED and DISABLED based on:
1. The list of running services on the system
2. The critical services mentioned in the README that MUST remain running
3. CyberPatriot security best practices

Return ONLY valid JSON in this exact format:
{
  "services_to_stop": [
    {
      "name": "service-name",
      "reason": "Brief explanation why this should be stopped"
    }
  ],
  "services_to_keep": [
    {
      "name": "service-name",
      "reason": "Brief explanation why this should remain running"
    }
  ]
}

Guidelines:
- NEVER recommend stopping critical services from the README
- NEVER recommend stopping essential system services (systemd, dbus, networkd, etc.)
- DO recommend stopping obviously unnecessary services like:
  - Web servers (apache2, nginx) UNLESS they are in critical services
  - FTP servers (vsftpd, proftpd) UNLESS they are in critical services
  - Database servers (mysql, postgresql, mongodb) UNLESS they are in critical services
  - File sharing (samba, nfs-server) UNLESS they are in critical services
  - Mail servers (postfix, dovecot, sendmail) UNLESS they are in critical services
  - DNS servers (bind9, named) UNLESS they are in critical services
  - Telnet, rsh, rlogin (always unsafe)
  - Avahi/mDNS (usually unnecessary)
  - SNMP (usually unnecessary)
- Consider that SSH is typically needed for administration
- Consider that desktop environments need display managers (gdm, lightdm, sddm)
- Consider that network management services are essential (NetworkManager, systemd-networkd)
- If unsure whether a service is needed, err on the side of keeping it running
- Return ONLY the JSON object, no additional text or explanation'

# Check if a package is installed
is_package_installed() {
    local package="$1"
    dpkg -l "$package" 2>/dev/null | grep -q "^ii"
}

# Install required packages
install_required_packages() {
    log_section "Installing Required Security Packages"

    local packages_to_install=()

    for package in "${REQUIRED_PACKAGES[@]}"; do
        if ! is_package_installed "$package"; then
            log_info "Package $package is not installed"
            packages_to_install+=("$package")
        else
            log_success "Package $package is already installed"
        fi
    done

    if [[ ${#packages_to_install[@]} -eq 0 ]]; then
        log_success "All required packages are already installed"
        return 0
    fi

    log_info "Installing packages: ${packages_to_install[*]}"

    # Install without apt update as requested
    if DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages_to_install[@]}" 2>&1 | tee -a "$BACKUP_DIR/apt_install.log"; then
        log_success "Successfully installed security packages"
    else
        log_warn "Some packages may have failed to install. Check $BACKUP_DIR/apt_install.log"
    fi
}

# Get all running services
get_running_services() {
    systemctl list-units --type=service --state=running --no-pager --no-legend | \
        awk '{print $1}' | sed 's/.service$//'
}

# Get all enabled services
get_enabled_services() {
    systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend | \
        awk '{print $1}' | sed 's/.service$//'
}

# Check if service exists
service_exists() {
    local service="$1"
    systemctl list-unit-files --type=service --all --no-pager --no-legend | \
        grep -q "^${service}.service"
}

# Start and enable a service
start_enable_service() {
    local service="$1"

    if ! service_exists "$service"; then
        log_warn "Service $service does not exist on this system"
        return 1
    fi

    local changed=0

    # Enable service
    if ! systemctl is-enabled --quiet "$service" 2>/dev/null; then
        log_info "Enabling $service..."
        if systemctl enable "$service" 2>&1 | tee -a "$BACKUP_DIR/service_changes.log"; then
            log_success "Enabled $service"
            changed=1
        else
            log_error "Failed to enable $service"
        fi
    else
        log_debug "$service is already enabled"
    fi

    # Start service if not running
    if ! systemctl is-active --quiet "$service" 2>/dev/null; then
        log_info "Starting $service..."
        if systemctl start "$service" 2>&1 | tee -a "$BACKUP_DIR/service_changes.log"; then
            log_success "Started $service"
            changed=1
        else
            log_error "Failed to start $service"
        fi
    else
        log_debug "$service is already running"
    fi

    return $changed
}

# Stop and disable a service
stop_disable_service() {
    local service="$1"
    local reason="${2:-No reason provided}"

    if ! service_exists "$service"; then
        log_debug "Service $service does not exist (already removed or never installed)"
        return 0
    fi

    log_info "Stopping and disabling $service"
    log_debug "Reason: $reason"

    local changed=0

    # Stop service if running
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        log_info "Stopping $service..."
        if systemctl stop "$service" 2>&1 | tee -a "$BACKUP_DIR/service_changes.log"; then
            log_success "Stopped $service"
            changed=1
        else
            log_error "Failed to stop $service"
        fi
    fi

    # Disable service if enabled
    if systemctl is-enabled --quiet "$service" 2>/dev/null; then
        log_info "Disabling $service..."
        if systemctl disable "$service" 2>&1 | tee -a "$BACKUP_DIR/service_changes.log"; then
            log_success "Disabled $service"
            changed=1
        else
            log_error "Failed to disable $service"
        fi
    fi

    # Mask the service for extra security (prevents manual start)
    if ! systemctl is-masked --quiet "$service" 2>/dev/null; then
        log_info "Masking $service..."
        if systemctl mask "$service" 2>&1 | tee -a "$BACKUP_DIR/service_changes.log"; then
            log_success "Masked $service"
            changed=1
        else
            log_warn "Failed to mask $service"
        fi
    fi

    return $changed
}

# Handle hardcoded services that should always be started
handle_always_start_services() {
    log_section "Enabling Critical Security Services"

    local changes_made=0

    for service in "${ALWAYS_START_SERVICES[@]}"; do
        if start_enable_service "$service"; then
            ((changes_made++))
        fi
    done

    if [[ $changes_made -gt 0 ]]; then
        log_success "Made $changes_made changes to critical security services"
    else
        log_success "All critical security services already configured correctly"
    fi
}

# Handle hardcoded services that should always be stopped
handle_always_stop_services() {
    log_section "Disabling Unnecessary Services (Hardcoded)"

    local changes_made=0

    for service in "${ALWAYS_STOP_SERVICES[@]}"; do
        if stop_disable_service "$service" "Always disabled for security"; then
            ((changes_made++))
        fi
    done

    if [[ $changes_made -gt 0 ]]; then
        log_success "Stopped/disabled $changes_made unnecessary services"
    else
        log_info "No hardcoded unnecessary services found running"
    fi
}

# Get AI recommendations for services
get_service_recommendations() {
    local running_services="$1"
    local critical_services="$2"

    if ! check_openrouter_config; then
        log_error "OpenRouter API not configured - skipping AI-based service analysis"
        return 1
    fi

    log_section "Analyzing Services with AI"
    log_info "Sending service list to AI for analysis..."

    # Construct the user prompt with service information
    local user_prompt="Running Services on the system:
$running_services

Critical Services from README (must remain running):
$critical_services

Please analyze these services and recommend which ones should be stopped/disabled for security."

    # Construct JSON payload
    local payload=$(jq -n \
        --arg model "$OPENROUTER_MODEL" \
        --arg system "$SERVICE_ANALYSIS_PROMPT" \
        --arg content "$user_prompt" \
        '{
            "model": $model,
            "messages": [
                {
                    "role": "system",
                    "content": $system
                },
                {
                    "role": "user",
                    "content": $content
                }
            ],
            "temperature": 0.1,
            "max_tokens": 3000
        }')

    # Make API request
    local response=$(curl -s -X POST "$OPENROUTER_API_URL" \
        -H "Authorization: Bearer $OPENROUTER_API_KEY" \
        -H "Content-Type: application/json" \
        -H "HTTP-Referer: https://github.com/cyberpatriot-linux-auto" \
        -d "$payload")

    if [[ $? -ne 0 ]]; then
        log_error "Failed to call OpenRouter API"
        return 1
    fi

    # Extract the content from response
    local content=$(echo "$response" | jq -r '.choices[0].message.content' 2>/dev/null)

    if [[ -z "$content" || "$content" == "null" ]]; then
        log_error "Failed to parse OpenRouter API response"
        log_debug "Response: $response"
        return 1
    fi

    log_debug "AI Response received"

    # Extract JSON from response
    local json_data=$(extract_json_from_response "$content")

    if [[ $? -ne 0 ]]; then
        log_error "Failed to extract valid JSON from AI response"
        return 1
    fi

    echo "$json_data"
    return 0
}

# Apply AI recommendations
apply_service_recommendations() {
    local recommendations="$1"

    log_section "Applying AI Service Recommendations"

    # Save recommendations to file
    mkdir -p "$SCRIPT_DIR/../data"
    echo "$recommendations" | jq '.' > "$SCRIPT_DIR/../data/service_recommendations.json"
    log_info "Saved recommendations to: $SCRIPT_DIR/../data/service_recommendations.json"

    # Display what will be kept
    log_info "Services recommended to KEEP running:"
    local keep_count=$(echo "$recommendations" | jq '.services_to_keep | length')
    if [[ $keep_count -gt 0 ]]; then
        echo "$recommendations" | jq -r '.services_to_keep[] | "  ✓ \(.name): \(.reason)"' | while read line; do
            log_success "$line"
        done
    else
        log_info "  (none specified)"
    fi

    echo ""

    # Apply stop recommendations
    log_info "Services recommended to STOP:"
    local stop_count=$(echo "$recommendations" | jq '.services_to_stop | length')

    if [[ $stop_count -eq 0 ]]; then
        log_info "  No services recommended for stopping"
        return 0
    fi

    local stopped_count=0

    echo "$recommendations" | jq -r '.services_to_stop[] | "\(.name)|\(.reason)"' | while IFS='|' read -r service reason; do
        log_info "Processing: $service"
        log_debug "Reason: $reason"

        if stop_disable_service "$service" "$reason"; then
            ((stopped_count++))
        fi
    done

    log_success "Processed $stop_count service stop recommendations"
}

# Main service auditing function
run_service_auditing() {
    log_section "Service Auditing Module"

    # Install required packages
    install_required_packages

    # Handle hardcoded services (always start)
    handle_always_start_services

    # Handle hardcoded services (always stop)
    handle_always_stop_services

    # Get running services
    log_section "Analyzing Dynamic Services"
    log_info "Gathering running services..."
    local running_services=$(get_running_services)
    local running_count=$(echo "$running_services" | wc -l)
    log_info "Found $running_count running services"

    # Get critical services from README
    local critical_services=""
    if [[ $README_PARSED -eq 1 ]]; then
        log_info "Retrieving critical services from README..."
        critical_services=$(get_critical_services 2>/dev/null || echo "")

        if [[ -n "$critical_services" ]]; then
            local critical_count=$(echo "$critical_services" | grep -v '^$' | wc -l)
            log_info "Found $critical_count critical services in README:"
            echo "$critical_services" | while read service; do
                [[ -n "$service" ]] && log_success "  - $service"
            done
        else
            log_warn "No critical services specified in README"
            critical_services="none"
        fi
    else
        log_warn "README not parsed - proceeding without critical services list"
        critical_services="none"
    fi

    # Get AI recommendations
    local recommendations=$(get_service_recommendations "$running_services" "$critical_services")

    if [[ $? -ne 0 || -z "$recommendations" ]]; then
        log_error "Failed to get AI service recommendations"
        log_warn "Service auditing completed with hardcoded rules only"
        return 1
    fi

    # Apply recommendations
    apply_service_recommendations "$recommendations"

    log_success "Service auditing completed successfully"
    return 0
}

export -f run_service_auditing
