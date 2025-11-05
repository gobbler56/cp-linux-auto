#!/bin/bash
# readme_parser.sh - README parsing module
# Finds, parses, and extracts structured information from CyberPatriot README files

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"
source "$SCRIPT_DIR/../lib/openrouter.sh"

# Paths to check for README files
README_CANDIDATES=(
    "/opt/aeacus/assets/ReadMe.html"  # Aeacus practice image
    "/home/*/Desktop/README.html"      # Common location
    "/root/Desktop/README.html"        # Root desktop
    "/tmp/README.html"                 # Temporary location
)

# Global variable to store parsed README data
declare -g README_DATA=""
declare -g README_PARSED=0

# Find README HTML file
find_readme_html() {
    log_debug "Searching for README.html file..."

    for pattern in "${README_CANDIDATES[@]}"; do
        # Use glob expansion
        for file in $pattern; do
            if [[ -f "$file" ]]; then
                log_info "Found README at: $file"
                echo "$file"
                return 0
            fi
        done
    done

    log_warn "No README.html file found in standard locations"
    return 1
}

# Read and parse README file
parse_readme() {
    local readme_path="$1"

    if [[ -z "$readme_path" ]]; then
        readme_path=$(find_readme_html)
        if [[ $? -ne 0 ]]; then
            log_error "Could not find README file"
            return 1
        fi
    fi

    if [[ ! -f "$readme_path" ]]; then
        log_error "README file does not exist: $readme_path"
        return 1
    fi

    log_section "Parsing README"
    log_info "Reading README from: $readme_path"

    # Read the HTML content
    local raw_html=$(cat "$readme_path")

    # Strip HTML tags to get plain text
    local plain_text=$(remove_html_tags "$raw_html")

    log_debug "Plain text length: ${#plain_text} characters"

    # Save plain text for debugging
    mkdir -p "$SCRIPT_DIR/../data"
    echo "$plain_text" > "$SCRIPT_DIR/../data/readme_plaintext.txt"
    log_debug "Saved plain text to: $SCRIPT_DIR/../data/readme_plaintext.txt"

    # Use OpenRouter to extract structured information
    log_info "Extracting structured information using AI..."
    local ai_response=$(invoke_readme_extraction "$plain_text" "$readme_path")

    if [[ $? -ne 0 ]]; then
        log_error "Failed to extract README information"
        return 1
    fi

    log_debug "AI Response:"
    log_debug "$ai_response"

    # Save raw AI response
    echo "$ai_response" > "$SCRIPT_DIR/../data/readme_ai_response.txt"

    # Extract and validate JSON
    local json_data=$(extract_json_from_response "$ai_response")

    if [[ $? -ne 0 ]]; then
        log_error "Failed to extract JSON from AI response"
        return 1
    fi

    # Validate JSON structure
    if ! echo "$json_data" | jq -e '.all_users' >/dev/null 2>&1; then
        log_error "Invalid JSON structure in AI response"
        return 1
    fi

    # Save parsed JSON
    echo "$json_data" | jq '.' > "$SCRIPT_DIR/../data/readme_parsed.json"
    log_info "Saved parsed data to: $SCRIPT_DIR/../data/readme_parsed.json"

    # Store in global variable
    README_DATA="$json_data"
    README_PARSED=1

    # Display summary
    display_readme_summary "$json_data"

    return 0
}

# Display summary of parsed README
display_readme_summary() {
    local json="$1"

    log_section "README Summary"

    local all_users_count=$(echo "$json" | jq '.all_users | length')
    local recent_hires_count=$(echo "$json" | jq '.recent_hires | length')
    local terminated_count=$(echo "$json" | jq '.terminated_users | length')
    local critical_services_count=$(echo "$json" | jq '.critical_services | length')

    log_info "Authorized Users: $all_users_count"
    if [[ $all_users_count -gt 0 ]]; then
        echo "$json" | jq -r '.all_users[] | "  - \(.name) (\(.account_type))"' | while read line; do
            log_debug "$line"
        done
    fi

    log_info "Recent Hires (to create): $recent_hires_count"
    if [[ $recent_hires_count -gt 0 ]]; then
        echo "$json" | jq -r '.recent_hires[] | "  - \(.name) (\(.account_type))"' | while read line; do
            log_debug "$line"
        done
    fi

    log_info "Terminated Users: $terminated_count"
    if [[ $terminated_count -gt 0 ]]; then
        echo "$json" | jq -r '.terminated_users[] | "  - \(.)"' | while read line; do
            log_debug "$line"
        done
    fi

    log_info "Critical Services: $critical_services_count"
    if [[ $critical_services_count -gt 0 ]]; then
        echo "$json" | jq -r '.critical_services[] | "  - \(.)"' | while read line; do
            log_debug "$line"
        done
    fi

    echo ""
}

# Get all authorized users
get_authorized_users() {
    if [[ $README_PARSED -eq 0 ]]; then
        log_error "README not parsed yet. Call parse_readme first."
        return 1
    fi

    echo "$README_DATA" | jq -r '.all_users[].name'
}

# Get authorized admin users
get_authorized_admins() {
    if [[ $README_PARSED -eq 0 ]]; then
        log_error "README not parsed yet. Call parse_readme first."
        return 1
    fi

    echo "$README_DATA" | jq -r '.all_users[] | select(.account_type == "admin") | .name'
}

# Get users to create
get_users_to_create() {
    if [[ $README_PARSED -eq 0 ]]; then
        log_error "README not parsed yet. Call parse_readme first."
        return 1
    fi

    echo "$README_DATA" | jq -r '.recent_hires[]'
}

# Get terminated users
get_terminated_users() {
    if [[ $README_PARSED -eq 0 ]]; then
        log_error "README not parsed yet. Call parse_readme first."
        return 1
    fi

    echo "$README_DATA" | jq -r '.terminated_users[]'
}

# Get critical services
get_critical_services() {
    if [[ $README_PARSED -eq 0 ]]; then
        log_error "README not parsed yet. Call parse_readme first."
        return 1
    fi

    echo "$README_DATA" | jq -r '.critical_services[]'
}

# Check if user is authorized
is_user_authorized() {
    local username="$1"

    if [[ $README_PARSED -eq 0 ]]; then
        return 1
    fi

    local count=$(echo "$README_DATA" | jq -r --arg user "$username" \
        '.all_users[] | select(.name == $user) | .name' | wc -l)

    [[ $count -gt 0 ]]
}

# Check if user should be admin
is_user_admin() {
    local username="$1"

    if [[ $README_PARSED -eq 0 ]]; then
        return 1
    fi

    local account_type=$(echo "$README_DATA" | jq -r --arg user "$username" \
        '.all_users[] | select(.name == $user) | .account_type')

    [[ "$account_type" == "admin" ]]
}

# Check if user is terminated
is_user_terminated() {
    local username="$1"

    if [[ $README_PARSED -eq 0 ]]; then
        return 1
    fi

    local count=$(echo "$README_DATA" | jq -r --arg user "$username" \
        '.terminated_users[] | select(. == $user)' | wc -l)

    [[ $count -gt 0 ]]
}

# Get groups to create
get_groups_to_create() {
    if [[ $README_PARSED -eq 0 ]]; then
        log_error "README not parsed yet. Call parse_readme first."
        return 1
    fi

    echo "$README_DATA" | jq -r '.groups_to_create[]?'
}

# Get system users to restrict
get_system_users_to_restrict() {
    if [[ $README_PARSED -eq 0 ]]; then
        log_error "README not parsed yet. Call parse_readme first."
        return 1
    fi

    echo "$README_DATA" | jq -r '.system_users_to_restrict[]?'
}

# Get user groups for a specific user
get_user_groups() {
    local username="$1"

    if [[ $README_PARSED -eq 0 ]]; then
        log_error "README not parsed yet. Call parse_readme first."
        return 1
    fi

    echo "$README_DATA" | jq -r --arg user "$username" \
        '.all_users[] | select(.name == $user) | .groups[]?'
}

# Export functions
export -f find_readme_html parse_readme display_readme_summary
export -f get_authorized_users get_authorized_admins get_users_to_create
export -f get_terminated_users get_critical_services
export -f is_user_authorized is_user_admin is_user_terminated
export -f get_groups_to_create get_system_users_to_restrict get_user_groups
