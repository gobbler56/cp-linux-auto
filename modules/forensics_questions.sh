#!/bin/bash
# forensics_questions.sh - Forensics Questions Module
# Handles discovery and AI-assisted answering of CyberPatriot forensic questions

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"
source "$SCRIPT_DIR/../lib/openrouter.sh"

# System prompt for the OpenRouter-powered forensic assistant
readonly FORENSICS_SYSTEM_PROMPT='You are a CyberPatriot Linux forensic analyst. Analyze the provided forensic question files an
d craft clear, concise answers that students can enter into the scoring report. When needed you may request exactly one safe, re
ad-only shell command to gather extra evidence (allowed commands: cat, ls, grep, find, strings, head, tail, sed, awk, wc, stat).
Only request a command if the supplied question text is insufficient. Always respond with valid JSON in the exact format:
{
  "answers": [
    {"number": 1, "answer": "Answer text", "explanation": "(optional short reasoning)"}
  ],
  "command_request": null | {"command": "cat /path", "reason": "Why the command is needed"}
}
Ensure answers directly address the question prompts. If no command is required set command_request to null.'

# Discover forensic question files on user desktops
discover_forensics_questions() {
    local -a entries=()
    local -a search_paths=("/home"/*/Desktop "/root/Desktop")

    for desktop in "${search_paths[@]}"; do
        [[ -d "$desktop" ]] || continue

        shopt -s nullglob
        local files=("$desktop"/Forensics\ Question\ *.txt)
        shopt -u nullglob

        for file in "${files[@]}"; do
            [[ -f "$file" ]] || continue

            local filename=$(basename "$file")
            if [[ "$filename" =~ ^Forensics[[:space:]]Question[[:space:]]([1-9])\.txt$ ]]; then
                local number="${BASH_REMATCH[1]}"
                local content
                content=$(cat "$file")
                local entry
                entry=$(jq -n \
                    --argjson number "$number" \
                    --arg path "$file" \
                    --arg content "$content" \
                    '{number: $number, path: $path, content: $content}'
                )
                entries+=("$entry")
            fi
        done
    done

    if (( ${#entries[@]} == 0 )); then
        echo "[]"
        return 0
    fi

    printf '%s\n' "${entries[@]}" | jq -s 'sort_by(.number)'
}

# Prepare the initial user message payload for OpenRouter
build_forensics_user_message() {
    local questions_json="$1"
    jq -n \
        --argjson questions "$questions_json" \
        '{
            task: "Analyze CyberPatriot forensic question files and produce answers.",
            instructions: {
                response_format: "Return JSON with keys answers (array) and command_request (null or object).",
                command_guidance: "You may request at most one safe, read-only shell command if the supplied data is insufficient."
            },
            questions: $questions
        }' | jq -c '.'
}

# Call OpenRouter with the provided chat history
call_forensics_openrouter() {
    local messages_json="$1"

    if ! check_openrouter_config; then
        return 1
    fi

    local payload
    payload=$(jq -n \
        --arg model "$OPENROUTER_MODEL" \
        --argjson messages "$messages_json" \
        '{
            model: $model,
            messages: $messages,
            temperature: 0.1,
            max_tokens: 7000
        }')

    local response
    response=$(curl -s -X POST "$OPENROUTER_API_URL" \
        -H "Authorization: Bearer $OPENROUTER_API_KEY" \
        -H "Content-Type: application/json" \
        -H "HTTP-Referer: https://github.com/cyberpatriot-linux-auto" \
        -d "$payload")

    if [[ $? -ne 0 ]]; then
        log_error "Failed to contact OpenRouter API"
        return 1
    fi

    local content
    content=$(echo "$response" | jq -r '.choices[0].message.content' 2>/dev/null)

    if [[ -z "$content" || "$content" == "null" ]]; then
        log_error "OpenRouter response did not contain content"
        log_debug "Response: $response"
        return 1
    fi

    echo "$content"
    return 0
}

# Validate that the requested command is safe to execute
is_safe_forensics_command() {
    local command="$1"
    local disallowed_chars='[;&`$><]'
    if [[ "$command" =~ $disallowed_chars || "$command" == *"||"* || "$command" == *"&&"* ]]; then
        return 1
    fi

    local first_word
    first_word=$(awk '{print $1}' <<<"$command")
    case "$first_word" in
        cat|ls|grep|find|strings|head|tail|sed|awk|wc|stat)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Execute an AI-requested command and capture output
execute_forensics_command() {
    local command="$1"

    if ! is_safe_forensics_command "$command"; then
        log_warn "Rejected unsafe command request: $command"
        jq -n \
            --arg command "$command" \
            '{command: $command, exit_code: 126, stdout: "", stderr: "Command rejected by policy"}'
        return 0
    fi

    local stdout_file stderr_file
    stdout_file=$(mktemp)
    stderr_file=$(mktemp)

    bash -c "$command" >"$stdout_file" 2>"$stderr_file"
    local exit_code=$?
    local stdout
    local stderr
    stdout=$(cat "$stdout_file")
    stderr=$(cat "$stderr_file")
    rm -f "$stdout_file" "$stderr_file"

    jq -n \
        --arg command "$command" \
        --arg stdout "$stdout" \
        --arg stderr "$stderr" \
        --argjson exit_code "$exit_code" \
        '{command: $command, exit_code: $exit_code, stdout: $stdout, stderr: $stderr}'
}

# Handle AI interaction workflow and return the final JSON payload of answers
obtain_forensics_answers() {
    local questions_json="$1"

    if ! check_openrouter_config; then
        return 1
    fi

    if ! check_dependencies curl jq; then
        log_error "curl and jq are required for AI-assisted forensics analysis"
        return 1
    fi

    local user_message
    user_message=$(build_forensics_user_message "$questions_json")

    local messages
    messages=$(jq -n \
        --arg system "$FORENSICS_SYSTEM_PROMPT" \
        --arg user "$user_message" \
        '[
            {"role": "system", "content": $system},
            {"role": "user", "content": $user}
        ]')

    local initial_content
    initial_content=$(call_forensics_openrouter "$messages") || return 1

    mkdir -p "$SCRIPT_DIR/../data"
    echo "$initial_content" > "$SCRIPT_DIR/../data/forensics_ai_initial.txt"

    local parsed_initial
    parsed_initial=$(extract_json_from_response "$initial_content") || {
        log_error "Failed to parse AI response for forensics questions"
        return 1
    }

    local command
    command=$(echo "$parsed_initial" | jq -r '.command_request.command // empty' 2>/dev/null || true)

    if [[ -n "$command" ]]; then
        local reason
        reason=$(echo "$parsed_initial" | jq -r '.command_request.reason // ""' 2>/dev/null || true)
        log_info "AI requested command: $command"
        [[ -n "$reason" ]] && log_info "Reason: $reason"

        local command_result
        command_result=$(execute_forensics_command "$command")

        echo "$command_result" | jq '.' > "$SCRIPT_DIR/../data/forensics_ai_command_result.json"
        local exit_code
        exit_code=$(echo "$command_result" | jq -r '.exit_code')
        log_info "Command exit code: $exit_code"

        local followup_user
        followup_user=$(jq -n \
            --argjson command_result "$command_result" \
            --argjson questions "$questions_json" \
            '{
                task: "Provide final answers using the supplied command output.",
                command_result: $command_result,
                questions: $questions
            }' | jq -c '.')

        local followup_messages
        followup_messages=$(jq -n \
            --arg system "$FORENSICS_SYSTEM_PROMPT" \
            --arg user1 "$user_message" \
            --arg assistant1 "$initial_content" \
            --arg user2 "$followup_user" \
            '[
                {"role": "system", "content": $system},
                {"role": "user", "content": $user1},
                {"role": "assistant", "content": $assistant1},
                {"role": "user", "content": $user2}
            ]')

        local followup_content
        followup_content=$(call_forensics_openrouter "$followup_messages") || return 1
        echo "$followup_content" > "$SCRIPT_DIR/../data/forensics_ai_followup.txt"

        extract_json_from_response "$followup_content"
        return $?
    else
        echo "$parsed_initial"
        return 0
    fi
}

# Module: Forensics Questions
# Category: Forensics Questions
# Description: Searches for forensic question files, reads their content, and obtains AI-assisted answers

run_forensics_questions() {
    log_info "Starting Forensics Questions module..."

    if ! check_dependencies jq; then
        log_error "jq is required for forensics question processing"
        return 1
    fi

    local questions_json
    questions_json=$(discover_forensics_questions)

    if [[ -z "$questions_json" || "$questions_json" == "[]" ]]; then
        log_warn "No Forensics Question text files found on user desktops"
        return 0
    fi

    mkdir -p "$SCRIPT_DIR/../data"
    echo "$questions_json" | jq '.' > "$SCRIPT_DIR/../data/forensics_questions.json"

    local question_count
    question_count=$(echo "$questions_json" | jq '. | length')
    log_info "Detected $question_count forensic question(s)"

    log_section "Forensics Questions"
    echo "$questions_json" | jq -r '.[] | "Question \(.number) (\(.path)):\n\(.content)\n"'

    local answers_json=""
    if check_openrouter_config; then
        log_info "Submitting forensic questions to AI assistant..."
        answers_json=$(obtain_forensics_answers "$questions_json") || {
            log_warn "AI-assisted analysis failed; displaying questions only"
            answers_json=""
        }
    else
        log_warn "OpenRouter API key not configured; skipping AI-assisted answers"
    fi

    if [[ -n "$answers_json" ]]; then
        echo "$answers_json" | jq '.' > "$SCRIPT_DIR/../data/forensics_answers.json"

        if echo "$answers_json" | jq -e '.answers and (.answers | type == "array")' >/dev/null 2>&1; then
            log_section "Forensics Answers"
            echo "$answers_json" | jq -r '.answers[] | "Question \(.number): \(.answer)"'
            if echo "$answers_json" | jq -e '.answers[] | select(has("explanation"))' >/dev/null 2>&1; then
                echo
                echo "$answers_json" | jq -r '.answers[] | select(has("explanation")) | "Q\(.number) Explanation: \(.explanation)"'
            fi
            log_success "Module forensics_questions completed successfully"
            return 0
        else
            log_warn "AI response did not include an answers array"
        fi
    fi

    log_info "Manual review of forensic questions may still be required"
    return 0
}

export -f run_forensics_questions
