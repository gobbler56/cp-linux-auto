#!/bin/bash
# cp-engine.sh - CyberPatriot Linux Remediation Engine
# Main script that orchestrates all security modules

set -euo pipefail

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load core libraries
source "$SCRIPT_DIR/lib/utils.sh"
source "$SCRIPT_DIR/lib/openrouter.sh"

# Default settings
SCORE_FILE="${SCORE_FILE:-/var/log/cyberpatriot/score.log}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/cyberpatriot}"

# All available modules (runs everything by default)
MODULES=(
    "dependencies"
    "readme_parser"
    "forensics_questions"
    "user_auditing"
    "account_policy"
    "security_policy"
    "prohibited_files"
    "malware"
    "unwanted_software"
    "ssh_hardening"
    "application_updates"
    "os_updates"
    "service_auditing"
    "local_policy"
    "defensive_countermeasures"
    "os_settings"
)

# Load configuration (only API key, model, and LOG_LEVEL)
CONFIG_FILE="$SCRIPT_DIR/config.conf"
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
    log_debug "Loaded configuration from: $CONFIG_FILE"
else
    log_warn "Configuration file not found: $CONFIG_FILE"
    log_warn "Using default settings"
fi

# Banner
show_banner() {
    echo -e "${COLOR_BOLD}${COLOR_CYAN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║   CyberPatriot Linux Auto-Remediation Engine                 ║
║   Version 1.0.0                                              ║
║   Supported: Linux Mint 21, Ubuntu 24                        ║
╚═══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${COLOR_RESET}"
}

# Check system compatibility
check_system() {
    log_section "System Check"

    local os=$(detect_os)
    local version=$(detect_os_version)

    log_info "Operating System: $os"
    log_info "OS Version: $version"

    if ! is_supported_os; then
        log_warn "This OS may not be fully supported"
        log_warn "Supported: Linux Mint 21.x, Ubuntu 24.x"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        log_success "OS is supported"
    fi
}

# Check dependencies
check_deps() {
    log_section "Dependency Check"

    local required_deps=("curl" "jq" "sed" "awk" "grep")
    local optional_deps=("clamav" "rkhunter" "lynis")

    log_info "Checking required dependencies..."
    if check_dependencies "${required_deps[@]}"; then
        log_success "All required dependencies installed"
    else
        log_error "Missing required dependencies. Please install them and try again."
        exit 1
    fi

    log_info "Checking optional dependencies..."
    for dep in "${optional_deps[@]}"; do
        if command_exists "$dep"; then
            log_success "  $dep: installed"
        else
            log_warn "  $dep: not installed (optional)"
        fi
    done
}

# Load a module
load_module() {
    local module_name="$1"
    local module_path="$SCRIPT_DIR/modules/${module_name}.sh"

    if [[ ! -f "$module_path" ]]; then
        log_error "Module not found: $module_name"
        return 1
    fi

    log_debug "Loading module: $module_name"
    source "$module_path"
    return 0
}

# Run a module
run_module() {
    local module_name="$1"

    log_section "Running Module: $module_name"

    # Load module if not already loaded
    if ! declare -f "run_${module_name}" >/dev/null 2>&1; then
        if ! load_module "$module_name"; then
            log_error "Failed to load module: $module_name"
            return 1
        fi
    fi

    # Check if module has run function
    if ! declare -f "run_${module_name}" >/dev/null 2>&1; then
        log_warn "Module $module_name does not have a run_${module_name} function"
        return 1
    fi

    # Run the module
    local start_time=$(date +%s)
    "run_${module_name}"
    local exit_code=$?
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    if [[ $exit_code -eq 0 ]]; then
        log_success "Module $module_name completed successfully (${duration}s)"
    else
        log_error "Module $module_name failed with exit code $exit_code (${duration}s)"
    fi

    return $exit_code
}

# Run all enabled modules
run_all_modules() {
    log_section "Running All Modules"

    local failed_modules=()
    local successful_modules=()

    for module in "${MODULES[@]}"; do
        # Skip comments
        [[ "$module" =~ ^#.*$ ]] && continue

        if run_module "$module"; then
            successful_modules+=("$module")
        else
            failed_modules+=("$module")
        fi
    done

    log_section "Execution Summary"
    log_info "Successful modules: ${#successful_modules[@]}"
    for module in "${successful_modules[@]}"; do
        log_success "  ✓ $module"
    done

    if [[ ${#failed_modules[@]} -gt 0 ]]; then
        log_info "Failed modules: ${#failed_modules[@]}"
        for module in "${failed_modules[@]}"; do
            log_error "  ✗ $module"
        done
    fi
}

# Interactive mode
interactive_mode() {
    log_section "Interactive Mode"

    while true; do
        echo
        echo "Available modules:"
        local i=1
        for module in "${MODULES[@]}"; do
            echo "  $i) $module"
            ((i++))
        done
        echo "  a) Run all modules"
        echo "  q) Quit"
        echo

        read -p "Select module to run: " choice

        if [[ "$choice" == "q" ]]; then
            log_info "Exiting interactive mode"
            exit 0
        elif [[ "$choice" == "a" ]]; then
            run_all_modules
            break
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -le ${#MODULES[@]} ]]; then
            local selected_module="${MODULES[$((choice-1))]}"
            run_module "$selected_module"

            echo
            read -p "Run another module? (y/n): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_info "Exiting interactive mode"
                exit 0
            fi
        else
            log_error "Invalid selection"
        fi
    done
}

# Show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
  -h, --help              Show this help message
  -i, --interactive       Run in interactive mode
  -m, --module MODULE     Run a specific module
  -a, --all               Run all enabled modules (default)
  -l, --list              List available modules
  -t, --test              Test OpenRouter API connection
  -c, --check             Check system and dependencies only

Modules:
$(for module in "${MODULES[@]}"; do echo "  - $module"; done)

Examples:
  $0                      # Run all modules
  $0 -m user_auditing     # Run user auditing module only
  $0 -i                   # Interactive mode
  $0 -t                   # Test API connection

Configuration:
  Edit config.conf to set your OpenRouter API key, model, and log level
EOF
}

# Main function
main() {
    local mode="all"
    local selected_module=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_usage
                exit 0
                ;;
            -i|--interactive)
                mode="interactive"
                shift
                ;;
            -m|--module)
                mode="single"
                selected_module="$2"
                shift 2
                ;;
            -a|--all)
                mode="all"
                shift
                ;;
            -l|--list)
                echo "Available modules:"
                for module in "${MODULES[@]}"; do
                    echo "  - $module"
                done
                exit 0
                ;;
            -t|--test)
                show_banner
                test_openrouter
                exit $?
                ;;
            -c|--check)
                show_banner
                check_system
                check_deps
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    # Show banner
    show_banner

    # Check root privileges
    require_root

    # Check system
    check_system

    # Check dependencies
    check_deps

    # Create necessary directories
    mkdir -p "$BACKUP_DIR"
    mkdir -p "$(dirname "$SCORE_FILE")"
    mkdir -p "$SCRIPT_DIR/data"

    # Run based on mode
    case "$mode" in
        all)
            run_all_modules
            ;;
        single)
            run_module "$selected_module"
            ;;
        interactive)
            interactive_mode
            ;;
    esac

    log_section "Complete"
    log_success "CyberPatriot remediation engine finished"
    log_info "Check score log: $SCORE_FILE"
}

# Run main function
main "$@"
