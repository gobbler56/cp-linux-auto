#!/bin/bash
# openrouter.sh - OpenRouter API interface for AI-powered README parsing
# Requires: curl, jq

source "$(dirname "${BASH_SOURCE[0]}")/utils.sh"

# OpenRouter API configuration
OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-}"
OPENROUTER_API_URL="https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL="${OPENROUTER_MODEL:-anthropic/claude-3.5-sonnet}"

# System prompt for README extraction (adapted from PowerShell version)
readonly SYSTEM_PROMPT='You are a specialized assistant that extracts structured information from CyberPatriot competition README files.

Your task is to parse the README content and extract:
1. All authorized users and their account types (admin or standard)
2. Recently hired users who need accounts created
3. Terminated users whose accounts should be removed
4. Critical services that must remain running
5. Group memberships for users
6. Groups that need to be created
7. System users that should have restricted login

Return ONLY valid JSON in this exact format:
{
  "all_users": [
    {"name": "username", "account_type": "admin|standard", "groups": ["group1", "group2"]}
  ],
  "recent_hires": [
    {"name": "username", "account_type": "admin|standard", "groups": ["group1"]}
  ],
  "terminated_users": ["username1", "username2"],
  "critical_services": ["ssh", "apache2"],
  "groups_to_create": [
    {"name": "groupname", "members": ["user1", "user2"]}
  ],
  "system_users_to_restrict": ["ftp", "guest", "mysql"]
}

Guidelines:
- Extract ALL users mentioned as authorized, including admins and regular users
- Identify users explicitly marked as "new hire", "recently hired", or "to be created"
- Identify users explicitly marked as "terminated", "removed", or "former"
- Service names should be actual service names (e.g., "ssh", "apache2", "mysql")
- Account types: "admin" for administrators, "standard" for regular users
- Extract any groups mentioned that should be created
- Extract group memberships for all users
- Identify system users (like "ftp", "guest") that should have login disabled
- If "ftp" user is NOT explicitly mentioned as authorized, add it to system_users_to_restrict
- If guest access is mentioned as disabled, add "guest" to system_users_to_restrict
- If information is not present, use empty arrays []
- Return ONLY the JSON object, no additional text or explanation'

# Check if API key is configured
check_openrouter_config() {
    if [[ -z "$OPENROUTER_API_KEY" ]]; then
        log_error "OpenRouter API key not configured"
        log_info "Set OPENROUTER_API_KEY environment variable or in config.conf"
        return 1
    fi
    return 0
}

# Remove HTML tags from content (similar to PowerShell version)
remove_html_tags() {
    local content="$1"

    # Remove head, script, and style tags with their content
    content=$(echo "$content" | sed -E 's|<head[^>]*>.*</head>||gI')
    content=$(echo "$content" | sed -E 's|<script[^>]*>.*</script>||gI')
    content=$(echo "$content" | sed -E 's|<style[^>]*>.*</style>||gI')

    # Remove all remaining HTML tags
    content=$(echo "$content" | sed -E 's|<[^>]+>||g')

    # Collapse multiple whitespace to single space
    content=$(echo "$content" | tr -s '[:space:]' ' ')

    # Trim leading/trailing whitespace
    content=$(echo "$content" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

    echo "$content"
}

# Call OpenRouter API with README content
invoke_readme_extraction() {
    local plain_text="$1"
    local url="${2:-unknown}"

    if ! check_openrouter_config; then
        return 1
    fi

    log_debug "Calling OpenRouter API for README extraction..."
    log_debug "Using model: $OPENROUTER_MODEL"

    # Construct JSON payload
    local payload=$(jq -n \
        --arg model "$OPENROUTER_MODEL" \
        --arg system "$SYSTEM_PROMPT" \
        --arg content "$plain_text" \
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
            "max_tokens": 4000
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

    echo "$content"
    return 0
}

# Extract JSON from model response (handles cases where model adds extra text)
extract_json_from_response() {
    local text="$1"

    # Try to parse as-is first
    if echo "$text" | jq -e '.' >/dev/null 2>&1; then
        echo "$text"
        return 0
    fi

    # Try to extract JSON object from text
    local extracted=$(echo "$text" | grep -oP '\{.*\}' | head -1)

    if [[ -n "$extracted" ]] && echo "$extracted" | jq -e '.' >/dev/null 2>&1; then
        echo "$extracted"
        return 0
    fi

    log_error "Could not extract valid JSON from model response"
    return 1
}

# Test OpenRouter connection
test_openrouter() {
    if ! check_openrouter_config; then
        return 1
    fi

    log_info "Testing OpenRouter API connection..."

    local test_payload=$(jq -n \
        --arg model "$OPENROUTER_MODEL" \
        '{
            "model": $model,
            "messages": [
                {
                    "role": "user",
                    "content": "Say hello"
                }
            ],
            "max_tokens": 10
        }')

    local response=$(curl -s -X POST "$OPENROUTER_API_URL" \
        -H "Authorization: Bearer $OPENROUTER_API_KEY" \
        -H "Content-Type: application/json" \
        -d "$test_payload")

    if echo "$response" | jq -e '.choices[0].message.content' >/dev/null 2>&1; then
        log_success "OpenRouter API connection successful"
        return 0
    else
        log_error "OpenRouter API connection failed"
        log_debug "Response: $response"
        return 1
    fi
}

export -f check_openrouter_config remove_html_tags invoke_readme_extraction
export -f extract_json_from_response test_openrouter
