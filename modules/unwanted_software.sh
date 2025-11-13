#!/bin/bash
# unwanted_software.sh - Unwanted Software Module
# Identifies and removes unauthorized or dangerous software

MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$MODULE_DIR/../lib/utils.sh"
source "$MODULE_DIR/../lib/openrouter.sh"

# Attempt to source README utilities for accessing global README context
if [[ -f "$MODULE_DIR/readme_parser.sh" ]]; then
    # shellcheck source=modules/readme_parser.sh
    source "$MODULE_DIR/readme_parser.sh"
fi

# Module: Unwanted Software
# Category: Unwanted Software
# Description: Removes unauthorized applications and potential security risks

read -r -d '' UNWANTED_SYSTEM_PROMPT <<'EOF'
You are an elite defensive cybersecurity analyst helping a CyberPatriot team triage Linux packages for removal.

You will receive:
- A curated list of high-risk offensive or non-compliant packages detected on the system.
- A snapshot of all manually installed packages (post-filtering to keep the list manageable).
- The mission README text that defines authorized tools and requirements.

Your goals:
1. Recommend which packages should be removed immediately to comply with CyberPatriot guidelines and hardening best practices.
2. Identify packages that require manual review because removal could impact mission requirements.
3. Reference the README when available to avoid recommending removal of authorized or mission-critical tools.
4. Provide actionable justifications grounded in offensive capability, policy violations, or mismatch with mission directives.
5. Packages can include but not limited to: hacking tools, games, torrent clients or media servers, and also, any legitimate service not mentioned in the readme. (Say ftp is authorized but nginx also exists on the system, but is not mentioned in the readme, that warrants nginx's removal while ftp remains.)

Output strictly valid JSON in the following format:
{
  "packages_to_remove": [
    {
      "package": "name",
      "reason": "clear, concise justification",
      "confidence": "high|medium|low",
      "source": "hardcoded_list|manual_scan|readme_conflict"
    }
  ],
  "packages_for_review": [
    {
      "package": "name",
      "reason": "why it needs a human decision",
      "notes": "important operational context"
    }
  ],
  "strategic_guidance": [
    "Additional recommendations or remediation tips"
  ]
}

Always tailor suggestions to CyberPatriot scoring priorities, avoid duplicates, and prefer removal of obviously offensive or gaming software unless the README authorizes it.
EOF

readonly UNWANTED_SYSTEM_PROMPT

read -r -d '' UNWANTED_PACKAGE_LIST <<'EOF'
ace aircrack-ng aisleriot amap android-sdk apache-users apktool apt2 arachni armitage arp-scan asleap backdoor-factory bbqsql bed beef besside-ng bettercap ettercap-common binwalk blindepephant bluelog bluemaho bluepot blueranger bluesnarfer braa brutespray bulk-extractor bully burpsuite capstone casefile cewl chntpw cisco-auditing-tool cisco-global-exploiter cisco-ocs cisco-torch cmospwd commix copy-router-config cowpattay crackle creddump crowbar crunch cryptcat cuckoo cutycapt cymothoa davtest dbd dc3dd ddrescue deblace deluge-common deluge-gtk dex2jar dff dhcpig dirb dirbuster distorm3 dns2tcp dnschef dnsenum dnsmap dnstracer dnswalk doona dotdotpwn dumpzilla eapmd5pass easside-ng edb-debugger enum4linux enumiax explooitdb extundelete eyewitness faraday fern-wifi-cracker fierce fiked fimap findmyhash firewalk five-or-more foremost four-in-a-row fragroute fragrouter freeradius-wpe funkload funkloader galleta gameconqueror ghost-phisher ghostphisher giskismet gnome-chess gnome-klotski gnome-mahjongg gnome-mines gnome-robots gnome-sudoku gnome-taquin gnome-tetravex gobuster golismero goofile gpp-decrypt gqrx grabber gr-scan guymager hampster-sidejack hashcat hash-identifier hexinject hexorbase hitori hostadp-wpe hping3 httptunnel hurl hydra iagno iaxflood ident-user-enum inspy intersect intrace inundator inviteflood iphone-backup-analyzer ismtp isr-evilgrade ivstools jad javasnoop jboss-autopwn jd-gui john johnny joomscan jsql-injection kalibrate-rtl keimpx killerbee kismet lbd lightsoff linux-exploit-suggester lynis makeivs-ng maltego-teeth manaplus maskprocessor masscan mdk3 metagoofil metasploit-framework mfcuk mfoc mfterm miranda mitmproxy msfpc multiforcer multimon-ng nbtscan ncrack nikto nishang nmap ntop oclgausscrack ohrwurm ollydbg openvas ophcrack oscanner osrframework p0f pack packetforge-ng padbuster paros parsero patator pdfid pdgmail peepdf phrasendrescher pixiewps plecost polenum powerfuzzer powersploit protos-sip proxystrike pwnat pyrit quadrapassel rainbow-crack rcracki-mt reaver rebind recon-ng redfang regripper remmina responder ridenum routersploit rsmangler rtlsdr-scanner rtpbreak rtpflood rtpinsertsound rtpmixsound sakis3g sbd sctpscan seclists set sfuzz shellnoob shellter sidguesser siparmyknife sipp sipvicious skipfish slowhttptest smali smbmap smtp-user-enum sniffjoke snmp-check sparta splsus spooftooph sqldict sqlmap sqlninja sqlsus sslsplit sslstrip sslyze statsprocessor sublist3r swell-foop t50 tali temineter thc-hydra thc-ipv6 thc-pptp-bruter thc-ssl-doc theharvester tkiptun-ng tlssled tnscmd10g toolkit transmission-cli transmission-common transmission-daemon transmission-gtk truecrach twofi u3-pwn ua-tester unicornscan uniscan unix-privesc-check valgrind vinagre voiphopper volatility w3af webscarab webshag webshells webslayer weevely wesside-ng wfuzz whatweb wifi-honey wifiphisher wifitap wifite winexe wireshark wordlists wpaclean wpscan xplico xspy xsser yara yersinia zaproxy
EOF

create_array_from_wordlist() {
    local -n __arr=$1
    local list="$2"

    __arr=()
    for pkg in $list; do
        __arr+=("$pkg")
    done
}

scan_hardcoded_packages() {
    local -n __hits=$1

    __hits=()

    local -a unwanted_packages
    create_array_from_wordlist unwanted_packages "$UNWANTED_PACKAGE_LIST"

    log_info "Scanning against high-risk package baseline (${#unwanted_packages[@]} entries)..."

    for pkg in "${unwanted_packages[@]}"; do
        if dpkg -s "$pkg" >/dev/null 2>&1; then
            log_warn "Detected high-risk package: $pkg"
            __hits+=("$pkg")
        else
            log_debug "Package not installed: $pkg"
        fi
    done

    log_info "High-risk scan complete: ${#__hits[@]} packages detected"
}

collect_manual_packages() {
    local -n __manual=$1

    __manual=()

    if ! command_exists apt-mark || ! command_exists comm; then
        log_warn "Manual package discovery unavailable (missing apt-mark or comm)"
        return 1
    fi

    local baseline_file="/var/log/installer/initial-status.gz"
    local manual_list=""

    if [[ -f "$baseline_file" ]]; then
        manual_list=$(comm -23 <(apt-mark showmanual | sort -u) <(gzip -dc "$baseline_file" | sed -n 's/^Package: //p' | sort -u) 2>/dev/null)
    else
        log_warn "Installer baseline not found; using raw manual package list"
        manual_list=$(apt-mark showmanual 2>/dev/null | sort -u)
    fi

    if [[ -z "$manual_list" ]]; then
        log_info "No manually installed packages detected"
        return 0
    fi

    while IFS= read -r pkg; do
        [[ -z "$pkg" ]] && continue
        [[ "$pkg" == python* ]] && continue
        __manual+=("$pkg")
    done <<< "$manual_list"

    if (( ${#__manual[@]} == 0 )); then
        log_info "Manual package list empty after filtering"
        return 0
    fi

    local max_packages=150
    if (( ${#__manual[@]} > max_packages )); then
        log_warn "Manual package list truncated to $max_packages entries for AI analysis"
        __manual=("${__manual[@]:0:max_packages}")
    fi

    log_info "Identified ${#__manual[@]} manually installed packages after filtering"
}

get_package_metadata_json() {
    local pkg="$1"

    local info
    info=$(dpkg-query -W -f='${Version}\t${Priority}\t${Section}\t${Description}\n' "$pkg" 2>/dev/null) || return 1

    local version priority section description
    IFS=$'\t' read -r version priority section description <<< "$info"

    version=${version:-unknown}
    priority=${priority:-unknown}
    section=${section:-unknown}
    description=${description//$'\n'/ }
    description=${description//$'\r'/ }
    description=$(echo "$description" | sed 's/[[:space:]]\+/ /g')
    [[ -z "$description" ]] && description="No description available"

    jq -n \
        --arg package "$pkg" \
        --arg version "$version" \
        --arg priority "$priority" \
        --arg section "$section" \
        --arg description "$description" \
        '{package: $package, version: $version, priority: $priority, section: $section, description: $description}'
}

create_package_array_json() {
    local -n __packages=$1

    if (( ${#__packages[@]} == 0 )); then
        echo "[]"
        return 0
    fi

    local -a json_entries=()
    for pkg in "${__packages[@]}"; do
        local metadata
        metadata=$(get_package_metadata_json "$pkg" 2>/dev/null)
        if [[ -n "$metadata" ]]; then
            json_entries+=("$metadata")
        else
            local fallback=$(jq -n --arg package "$pkg" '{package: $package, note: "metadata unavailable"}')
            json_entries+=("$fallback")
        fi
    done

    local json="["
    for i in "${!json_entries[@]}"; do
        (( i > 0 )) && json+="," 
        json+="${json_entries[$i]}"
    done
    json+="]"

    echo "$json"
}

get_readme_plain_text() {
    local data_dir="$MODULE_DIR/../data"
    local plain_path="$data_dir/readme_plaintext.txt"

    if [[ -f "$plain_path" ]]; then
        cat "$plain_path"
        return 0
    fi

    local readme_path=""
    if type -t find_readme_html >/dev/null 2>&1; then
        readme_path=$(find_readme_html 2>/dev/null)
    fi

    if [[ -z "$readme_path" || ! -f "$readme_path" ]]; then
        log_warn "README content unavailable"
        return 1
    fi

    local raw_html
    raw_html=$(cat "$readme_path")

    if type -t remove_html_tags >/dev/null 2>&1; then
        remove_html_tags "$raw_html"
    else
        log_warn "Falling back to raw README HTML"
        echo "$raw_html"
    fi
    return 0
}

invoke_unwanted_package_analysis() {
    local hardcoded_json="$1"
    local manual_json="$2"
    local readme_text="$3"

    if ! check_openrouter_config; then
        return 1
    fi

    local user_payload=$(jq -n \
        --argjson hardcoded "$hardcoded_json" \
        --argjson manual "$manual_json" \
        --arg readme "$readme_text" \
        '{task: "Assess unwanted software for removal", hardcoded_detections: $hardcoded, manual_packages: $manual, readme_content: $readme}')

    local payload=$(jq -n \
        --arg model "$OPENROUTER_MODEL" \
        --arg system "$UNWANTED_SYSTEM_PROMPT" \
        --arg content "$user_payload" \
        '{
            "model": $model,
            "messages": [
                {"role": "system", "content": $system},
                {"role": "user", "content": $content}
            ],
            "temperature": 0.0,
            "max_tokens": 12000
        }')

    local response=$(curl -s -X POST "$OPENROUTER_API_URL" \
        -H "Authorization: Bearer $OPENROUTER_API_KEY" \
        -H "Content-Type: application/json" \
        -H "HTTP-Referer: https://github.com/cyberpatriot-linux-auto" \
        -d "$payload")

    if [[ $? -ne 0 ]]; then
        log_error "Failed to contact OpenRouter API"
        return 1
    fi

    local content=$(echo "$response" | jq -r '.choices[0].message.content' 2>/dev/null)
    if [[ -z "$content" || "$content" == "null" ]]; then
        log_error "OpenRouter response missing content"
        log_debug "Response: $response"
        return 1
    fi

    echo "$content"
    return 0
}

run_unwanted_software() {
    log_info "Starting Unwanted Software module..."

    if ! command_exists dpkg-query; then
        log_error "dpkg-query command is required for package inspection"
        return 1
    fi

    if ! check_dependencies jq; then
        return 1
    fi

    mkdir -p "$MODULE_DIR/../data"

    local -a hardcoded_hits=()
    scan_hardcoded_packages hardcoded_hits

    local hardcoded_json=$(create_package_array_json hardcoded_hits)
    echo "$hardcoded_json" | jq '.' > "$MODULE_DIR/../data/unwanted_hardcoded_hits.json"

    local -a manual_packages=()
    collect_manual_packages manual_packages

    local manual_json=$(create_package_array_json manual_packages)
    echo "$manual_json" | jq '.' > "$MODULE_DIR/../data/unwanted_manual_packages.json"

    local readme_content=""
    if readme_content=$(get_readme_plain_text 2>/dev/null); then
        log_info "README context loaded (${#readme_content} characters)"
    else
        readme_content=""
        log_warn "Proceeding without README context"
    fi

    local use_ai=1
    if [[ -z "$OPENROUTER_API_KEY" ]]; then
        log_warn "OpenRouter not configured; skipping AI triage"
        use_ai=0
    elif ! command_exists curl; then
        log_error "curl is required for OpenRouter integration"
        use_ai=0
    fi

    if (( use_ai == 0 )); then
        return 0
    fi

    log_info "Submitting package data to AI for remediation guidance..."
    local ai_response=$(invoke_unwanted_package_analysis "$hardcoded_json" "$manual_json" "$readme_content")
    if [[ $? -ne 0 || -z "$ai_response" ]]; then
        log_error "Failed to obtain AI guidance for unwanted software"
        return 1
    fi

    echo "$ai_response" > "$MODULE_DIR/../data/unwanted_software_ai_raw.txt"

    local parsed_json=$(extract_json_from_response "$ai_response")
    if [[ $? -ne 0 ]]; then
        log_error "AI response did not contain valid JSON"
        return 1
    fi

    echo "$parsed_json" | jq '.' > "$MODULE_DIR/../data/unwanted_software_ai_analysis.json"

    local removal_count=$(echo "$parsed_json" | jq '.packages_to_remove | length' 2>/dev/null)
    local review_count=$(echo "$parsed_json" | jq '.packages_for_review | length' 2>/dev/null)

    log_section "AI Unwanted Software Recommendations"
    log_info "Packages to remove: ${removal_count:-0}"
    if [[ "$removal_count" =~ ^[0-9]+$ ]] && (( removal_count > 0 )); then
        echo "$parsed_json" \
            | jq -r '.packages_to_remove[] | "- \(.package): \(.reason) [confidence: \(.confidence)]"' \
            | while read -r line; do
                log_warn "$line"
            done
    fi

    log_info "Packages for manual review: ${review_count:-0}"
    if [[ "$review_count" =~ ^[0-9]+$ ]] && (( review_count > 0 )); then
        echo "$parsed_json" | jq -r '.packages_for_review[] | "- \(.package): \(.reason)"' | while read -r line; do
            log_info "$line"
        done
    fi

    if echo "$parsed_json" | jq -e '.strategic_guidance | length > 0' >/dev/null 2>&1; then
        log_info "Strategic guidance:"
        echo "$parsed_json" | jq -r '.strategic_guidance[]' | while read -r tip; do
            log_info "  - $tip"
        done
    fi

    return 0
}

export -f run_unwanted_software
