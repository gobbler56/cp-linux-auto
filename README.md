# CyberPatriot Linux Auto-Remediation Engine

A comprehensive, modular security remediation engine for CyberPatriot Linux competitions. Supports **Linux Mint 21** and **Ubuntu 24**.

## Features

- **Modular Architecture**: 13+ independent security modules that can be enabled/disabled
- **AI-Powered README Parsing**: Uses OpenRouter AI to extract structured information from README files
- **Automated Security Checks**: Comprehensive vulnerability scanning and remediation
- **Score Tracking**: Logs all remediation actions for scoring verification
- **Backup System**: Automatically backs up files before modification
- **Flexible Configuration**: Easy-to-edit configuration file for customization

## Project Structure

```
cp-linux-auto/
├── cp-engine.sh              # Main engine script
├── config.conf               # Configuration file
├── lib/                      # Core libraries
│   ├── utils.sh             # Utility functions
│   └── openrouter.sh        # OpenRouter API interface
├── modules/                  # Security modules
│   ├── readme_parser.sh     # README parsing (non-modular, runs first)
│   ├── forensics_questions.sh
│   ├── user_auditing.sh
│   ├── account_policy.sh
│   ├── prohibited_files.sh
│   ├── malware.sh
│   ├── unwanted_software.sh
│   ├── ssh_hardening.sh
│   ├── application_updates.sh
│   ├── os_updates.sh
│   ├── service_auditing.sh
│   ├── local_policy.sh
│   ├── defensive_countermeasures.sh
│   └── os_settings.sh
└── data/                     # Runtime data and logs
    ├── readme_parsed.json   # Parsed README data
    └── readme_plaintext.txt # README plain text
```

## Quick Start

### 1. Installation

```bash
# Clone the repository
git clone <repository-url>
cd cp-linux-auto

# Make the main script executable
chmod +x cp-engine.sh

# Install dependencies
sudo apt-get update
sudo apt-get install curl jq
```

### 2. Configuration

Edit `config.conf` and set your OpenRouter API key:

```bash
# Get API key from: https://openrouter.ai/
OPENROUTER_API_KEY="your_api_key_here"
```

### 3. Usage

```bash
# Run all modules (requires root)
sudo ./cp-engine.sh

# Run in interactive mode
sudo ./cp-engine.sh -i

# Run specific module
sudo ./cp-engine.sh -m user_auditing

# Test API connection
sudo ./cp-engine.sh -t

# Check system compatibility
sudo ./cp-engine.sh -c

# Show help
./cp-engine.sh -h
```

## Modules

### 1. **README Parser** (Core Module)
- Automatically finds README.html files
- Strips HTML content and extracts plain text
- Uses OpenRouter AI to parse structured information
- Provides data to all other modules

### 2. **Forensics Questions**
- Identifies forensics questions in README
- Helps answer common forensics questions
- Saves answers for manual submission

### 3. **User Auditing**
- Compares system users against README authorized list
- Identifies unauthorized users
- Detects terminated users with active accounts
- Creates missing authorized users
- Verifies admin privileges

### 4. **Account Policy**
- Configures password complexity requirements
- Sets password aging policies
- Configures account lockout
- Enforces minimum password length
- Sets up password history

### 5. **Prohibited Files**
- Scans for prohibited media files (.mp3, .mp4, etc.)
- Identifies hacking tools and unauthorized software
- Generates reports of found files
- Optional automatic removal

### 6. **Malware**
- Runs ClamAV virus scans
- Executes rkhunter for rootkit detection
- Checks for suspicious processes
- Scans for backdoors and reverse shells
- Examines cron jobs and startup scripts

### 7. **Unwanted Software**
- Lists all installed packages
- Identifies hacking tools (nmap, john, hydra, etc.)
- Detects P2P software and games
- Recommends packages for removal

### 8. **SSH Hardening**
- Comprehensive SSH server hardening (PermitRootLogin, PasswordAuthentication, etc.)
- Configures strong cryptographic algorithms (ciphers, MACs, key exchange)
- Hardens SSH file and directory permissions
- Creates SSH banner for unauthorized access warnings
- Removes weak Diffie-Hellman moduli (>= 3071-bit only)
- Configures UFW firewall rules for custom SSH ports
- Sets up user SSH directories and authorized_keys
- Validates configuration before applying changes
- Supports Ubuntu 24.04 and Linux Mint 21

### 9. **Application Updates**
- Updates package lists
- Checks for available application updates
- Installs security patches
- Handles snap and flatpak packages

### 10. **OS Updates**
- Checks kernel version and updates
- Installs OS security patches
- Configures automatic security updates
- Detects required system reboots

### 11. **Service Auditing**
- Lists all running services
- Ensures critical services are running
- Identifies unnecessary/dangerous services
- Manages service startup configuration

### 12. **Local Policy**
- Configures sudo permissions
- Sets secure file permissions
- Configures audit logging (auditd)
- Sets secure umask values

### 13. **Defensive Countermeasures**
- Enables and configures UFW firewall
- Sets up fail2ban for intrusion prevention
- Enables auditd for system auditing
- Configures file integrity monitoring (AIDE)

### 14. **OS Settings**
- Configures kernel security parameters (sysctl)
- Disables unnecessary kernel modules
- Sets up system banners
- Configures DNS and network settings

## README Parsing

The engine uses OpenRouter AI to parse README files similar to your Windows version. It extracts:

- **Authorized Users**: All users who should have accounts
- **Authorized Admins**: Users who should have administrator privileges
- **Recent Hires**: New users that need accounts created
- **Terminated Users**: Users whose accounts should be removed
- **Critical Services**: Services that must remain running
- **Group Memberships**: User group assignments

### Example README Structure

The parser can handle various README formats and extracts information about:
- User lists with roles
- Service requirements
- Forensics questions
- Specific security directives

## Linux Mint 21 vs Ubuntu 24 Differences

### Package Management
- **Both**: Use APT package manager (`apt-get`, `apt`)
- **Mint 21**: Based on Ubuntu 22.04 LTS (Jammy)
- **Ubuntu 24**: Uses newer package versions

### Display Manager
- **Mint 21**: Uses LightDM by default (Cinnamon edition)
- **Ubuntu 24**: Uses GDM3 (GNOME Display Manager)

### Desktop Environment
- **Mint 21**: Cinnamon, MATE, or Xfce
- **Ubuntu 24**: GNOME (typically newer version)

### Default Applications
- **Mint 21**: Custom Mint tools (mintUpdate, mintInstall, etc.)
- **Ubuntu 24**: GNOME/Ubuntu-specific tools

### System Services
- **Both**: Use systemd for service management
- **Mint 21**: May have Mint-specific services
- **Ubuntu 24**: May have Ubuntu-specific services

### Software Sources
- **Mint 21**: Uses Mint and Ubuntu 22.04 repositories
- **Ubuntu 24**: Uses Ubuntu 24.04 repositories
- **Note**: Some PPAs may differ between versions

### Key Locations to Check

Both distributions share:
- User accounts: `/etc/passwd`, `/etc/shadow`
- Groups: `/etc/group`
- Sudoers: `/etc/sudoers`, `/etc/sudoers.d/`
- SSH config: `/etc/ssh/sshd_config`
- PAM config: `/etc/pam.d/`
- Service configs: `/etc/systemd/system/`

### Module Compatibility

All modules in this engine are designed to work with both distributions:
- Use systemd commands (not init.d)
- Check for both distribution-specific paths
- Use APT for package management
- Handle both Cinnamon/MATE (Mint) and GNOME (Ubuntu) settings

## Configuration Options

### API Settings
```bash
OPENROUTER_API_KEY=""          # Your OpenRouter API key
OPENROUTER_MODEL=""            # AI model to use
```

### Logging
```bash
LOG_LEVEL=1                    # 0=DEBUG, 1=INFO, 2=WARN, 3=ERROR
SCORE_FILE=""                  # Path to score log file
BACKUP_DIR=""                  # Path for backups
```

### Module Settings
```bash
MODULES=(...)                  # List of modules to run
CHECK_UNAUTHORIZED_USERS=true  # Enable/disable features
REMOVE_UNAUTHORIZED_USERS=false
# ... and many more settings
```

## Extending the Engine

### Adding a New Module

1. Create module file: `modules/my_module.sh`

```bash
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

run_my_module() {
    log_info "Starting My Module..."

    # Your implementation here

    return 0
}

export -f run_my_module
```

2. Add to `config.conf`:

```bash
MODULES=(
    # ... existing modules
    "my_module"
)
```

3. Run: `sudo ./cp-engine.sh -m my_module`

### Removing a Module

Simply comment out or remove the module name from the `MODULES` array in `config.conf`:

```bash
MODULES=(
    "user_auditing"
    # "unwanted_software"  # Disabled
    "account_policy"
)
```

## Development Status

### ✅ Complete
- Core engine architecture
- Module loading system
- OpenRouter API integration
- README HTML parsing
- Configuration system
- Logging and utilities
- All module scaffolds

### 🚧 To Be Implemented
- Full implementation of each module's functionality
- Specific remediation actions
- Automated fixing capabilities
- Testing and validation

## Dependencies

### Required
- `bash` (4.0+)
- `curl` - For API calls
- `jq` - For JSON parsing
- `sed`, `awk`, `grep` - Text processing

### Optional (for specific modules)
- `clamav` - Virus scanning
- `rkhunter` - Rootkit detection
- `fail2ban` - Intrusion prevention
- `ufw` - Firewall management
- `auditd` - System auditing
- `aide` - File integrity monitoring

Install optional dependencies:
```bash
sudo apt-get install clamav rkhunter fail2ban ufw auditd aide
```

## Scoring

All remediation actions are logged to the score file (default: `/var/log/cyberpatriot/score.log`):

```
[2025-11-04_10:30:15] +2 points: Disabled root SSH login
[2025-11-04_10:30:22] +3 points: Removed unauthorized user: hacker
[2025-11-04_10:30:45] +1 points: Updated all packages
```

## Best Practices

1. **Always backup**: The engine backs up files automatically, but keep system snapshots
2. **Test first**: Run with `-c` to check compatibility before full run
3. **Review actions**: Check logs and score file after execution
4. **Manual verification**: Always verify critical changes manually
5. **README first**: Ensure README is parsed correctly before running remediation

## Troubleshooting

### OpenRouter API Issues
```bash
# Test API connection
sudo ./cp-engine.sh -t

# Check API key in config.conf
cat config.conf | grep OPENROUTER_API_KEY
```

### Module Not Running
```bash
# Check if module exists
ls -l modules/

# Try running module directly
sudo ./cp-engine.sh -m module_name

# Check logs for errors
tail -f /var/log/cyberpatriot/score.log
```

### Permission Denied
```bash
# Ensure running as root
sudo ./cp-engine.sh

# Check file permissions
chmod +x cp-engine.sh
```

## Contributing

When implementing module functionality:
1. Follow existing code style
2. Use utility functions from `lib/utils.sh`
3. Add logging for all actions
4. Back up files before modification
5. Use `log_score()` for scoring events
6. Test on both Mint 21 and Ubuntu 24

## License

This project is designed for CyberPatriot competition use.

## Support

- Check README.md (this file)
- Review module comments for implementation TODOs
- Test on practice images before competition

---

**Note**: This is a scaffold implementation. Module functionality needs to be implemented based on specific CyberPatriot competition requirements and your team's strategy.
