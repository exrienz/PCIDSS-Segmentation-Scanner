#!/bin/bash
#===============================================================================
# CDE Segmentation Scanner
# Purpose: Scan from NON-CDE segment to CDE environment using masscan + nmap
# Features: Auto-resume, comprehensive logging, nmap verification
#===============================================================================

set -e

#===============================================================================
# CONFIGURATION - MODIFY THESE VALUES FOR YOUR ENVIRONMENT
#===============================================================================

# CDE Target Range(s) - Add your CDE IP ranges here
# Examples: "10.0.0.0/24" or "192.168.100.0/24,192.168.101.0/24"
CDE_TARGETS="${CDE_TARGETS:-10.0.0.0/24}"

# Port range to scan (0-65535 for all ports)
PORT_RANGE="${PORT_RANGE:-0-65535}"

# Scan rate (packets per second) - adjust based on network capacity
# Start low (100-1000) and increase if network can handle it
SCAN_RATE="${SCAN_RATE:-1000}"

# Your NON-CDE source IP (leave empty for auto-detect)
SOURCE_IP="${SOURCE_IP:-}"

# Network interface to use (leave empty for auto-detect)
INTERFACE="${INTERFACE:-}"

# Enable nmap verification after masscan (true/false)
# This provides more accurate results but takes longer
NMAP_VERIFY="${NMAP_VERIFY:-true}"

# Nmap additional options (service detection, scripts, etc.)
NMAP_OPTIONS="${NMAP_OPTIONS:--sV -sC --version-intensity 5}"

# Maximum parallel nmap scans
NMAP_PARALLEL="${NMAP_PARALLEL:-5}"

# Source IP ranges for the report (your NON-CDE segment)
# This appears in the PCI-DSS report as the source
SOURCE_RANGES="${SOURCE_RANGES:-}"

#===============================================================================
# PATHS AND DIRECTORIES
#===============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/scan_results"
CONFIG_DIR="${SCRIPT_DIR}/config"
RESUME_FILE="${SCRIPT_DIR}/paused.conf"
EXCLUDE_FILE="${CONFIG_DIR}/exclude.txt"
TARGETS_FILE="${CONFIG_DIR}/targets.txt"

#===============================================================================
# TIMESTAMP AND FILE NAMING
#===============================================================================

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

#===============================================================================
# HELPER FUNCTION: Create session ID from source ranges
#===============================================================================

get_session_id() {
    local source="$1"
    # Create a safe directory name from source ranges
    # Replace special characters with underscores
    local session_id="${source//\//_}"
    session_id="${session_id//./_}"
    session_id="${session_id// /_}"
    session_id="${session_id//,/_}"
    echo "$session_id"
}

#===============================================================================
# OUTPUT FILES (will be set after source is known)
#===============================================================================

# These will be set in setup_session_dirs() after SOURCE_RANGES is known
SESSION_DIR=""
SCAN_NAME=""
JSON_OUTPUT=""
GNMAP_OUTPUT=""
LIST_OUTPUT=""
XML_OUTPUT=""
CONSOLE_LOG=""
SUMMARY_FILE=""
PER_TARGET_DIR=""
COMPLETED_FILE=""

# Nmap verification output files
NMAP_DIR=""
NMAP_TARGETS=""
NMAP_COMBINED=""
NMAP_XML=""
VERIFIED_PORTS=""

setup_session_dirs() {
    local session_id=$(get_session_id "$SOURCE_RANGES")
    
    SESSION_DIR="${LOG_DIR}/sessions/${session_id}"
    SCAN_NAME="scan_${TIMESTAMP}"
    
    # Create session directory
    mkdir -p "$SESSION_DIR"
    
    # Set all output paths
    JSON_OUTPUT="${SESSION_DIR}/${SCAN_NAME}.json"
    GNMAP_OUTPUT="${SESSION_DIR}/${SCAN_NAME}.gnmap"
    LIST_OUTPUT="${SESSION_DIR}/${SCAN_NAME}.txt"
    XML_OUTPUT="${SESSION_DIR}/${SCAN_NAME}.xml"
    CONSOLE_LOG="${SESSION_DIR}/console.log"
    SUMMARY_FILE="${SESSION_DIR}/summary.md"
    PER_TARGET_DIR="${SESSION_DIR}/per_target"
    COMPLETED_FILE="${SESSION_DIR}/.completed_targets"
    
    # Nmap directories
    NMAP_DIR="${SESSION_DIR}/nmap_verification"
    NMAP_TARGETS="${NMAP_DIR}/targets_to_verify.txt"
    NMAP_COMBINED="${NMAP_DIR}/nmap_combined.txt"
    NMAP_XML="${NMAP_DIR}/nmap_combined.xml"
    VERIFIED_PORTS="${NMAP_DIR}/verified_ports.txt"
    
    mkdir -p "$PER_TARGET_DIR"
    
    # Save source ranges to session
    echo "$SOURCE_RANGES" > "${SESSION_DIR}/.source_ranges"
    
    log_info "Session directory: $SESSION_DIR"
}

#===============================================================================
# COLORS FOR OUTPUT
#===============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

#===============================================================================
# FUNCTIONS
#===============================================================================

# Ensure log directory exists before logging
ensure_log_dir() {
    if [[ ! -d "$LOG_DIR" ]]; then
        mkdir -p "$LOG_DIR"
    fi
}

# Log with optional file output
log_to_file() {
    local message="$1"
    if [[ -n "$CONSOLE_LOG" && -n "$SESSION_DIR" ]]; then
        echo -e "$message" | tee -a "$CONSOLE_LOG"
    else
        echo -e "$message"
    fi
}

log_info() {
    ensure_log_dir
    log_to_file "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_success() {
    ensure_log_dir
    log_to_file "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warning() {
    ensure_log_dir
    log_to_file "${YELLOW}[WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    ensure_log_dir
    log_to_file "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           CDE SEGMENTATION SCANNER (MASSCAN)                 ║"
    echo "║          NON-CDE to CDE Network Assessment                   ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (sudo)"
        exit 1
    fi
}

check_masscan() {
    if ! command -v masscan &> /dev/null; then
        log_error "masscan is not installed. Please install it first:"
        echo "  macOS:   brew install masscan"
        echo "  Ubuntu:  apt-get install masscan"
        echo "  CentOS:  yum install masscan"
        exit 1
    fi
    log_success "masscan found: $(masscan --version 2>&1 | head -n1)"
}

check_nmap() {
    if [[ "$NMAP_VERIFY" == "true" ]]; then
        if ! command -v nmap &> /dev/null; then
            log_warning "nmap is not installed. Nmap verification will be skipped."
            log_info "Install nmap for more accurate results:"
            echo "  macOS:   brew install nmap"
            echo "  Ubuntu:  apt-get install nmap"
            echo "  CentOS:  yum install nmap"
            NMAP_VERIFY="false"
        else
            log_success "nmap found: $(nmap --version 2>&1 | head -n1)"
        fi
    fi
}

setup_directories() {
    mkdir -p "$LOG_DIR"
    mkdir -p "$CONFIG_DIR"
    # Session-specific directories (like NMAP_DIR) are created in setup_session_dirs()
}

create_default_configs() {
    # Create default exclude file if not exists
    if [[ ! -f "$EXCLUDE_FILE" ]]; then
        cat > "$EXCLUDE_FILE" << 'EOF'
# CDE Scan Exclusion List
# Add IP addresses or ranges to exclude from scanning
# One entry per line, supports CIDR notation
# Example:
# 10.0.0.1
# 10.0.0.0/30
EOF
        log_info "Created default exclude file: $EXCLUDE_FILE"
    fi

    # Create default targets file if not exists
    if [[ ! -f "$TARGETS_FILE" ]]; then
        cat > "$TARGETS_FILE" << 'EOF'
# CDE Target List
# Add your CDE IP ranges here, one per line
# Supports CIDR notation
# Example:
# 10.0.0.0/24
# 192.168.100.0/24
# 172.16.0.0/16
EOF
        log_info "Created default targets file: $TARGETS_FILE"
    fi
}

show_config() {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                    SCAN CONFIGURATION                        ${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}Source (Non-CDE):${NC}  ${SOURCE_RANGES:-Not set}"
    echo ""
    echo -e "  ${YELLOW}Target CDE Range:${NC}  (from targets.txt)"
    echo -e "  ${YELLOW}Port Range:${NC}        $PORT_RANGE"
    echo -e "  ${YELLOW}Scan Rate:${NC}         $SCAN_RATE pps"
    echo -e "  ${YELLOW}Source IP:${NC}         ${SOURCE_IP:-Auto-detect}"
    echo ""
    echo -e "${CYAN}─────────────────────────────────────────────────────────────${NC}"
    echo -e "  ${YELLOW}Nmap Verify:${NC}       $NMAP_VERIFY"
    if [[ "$NMAP_VERIFY" == "true" ]]; then
        echo -e "  ${YELLOW}Nmap Options:${NC}      $NMAP_OPTIONS"
    fi
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

prompt_source_ranges() {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}              STEP 1: SET YOUR SOURCE SEGMENT                 ${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    if [[ -n "$SOURCE_RANGES" ]]; then
        echo -e "  ${GREEN}Current Source (Non-CDE):${NC} $SOURCE_RANGES"
        echo ""
        echo -e "${YELLOW}Keep this source? (y/n)${NC}"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi
    
    echo -e "  Enter your NON-CDE source IP range(s)"
    echo -e "  ${BLUE}Example: 10.240.32.0/21, 10.240.40.0/21${NC}"
    echo ""
    echo -ne "  ${YELLOW}Source Range(s):${NC} "
    read -r SOURCE_RANGES
    
    if [[ -z "$SOURCE_RANGES" ]]; then
        SOURCE_RANGES="NON-CDE Segment"
        log_warning "No source range provided. Using default: '$SOURCE_RANGES'"
    fi
    
    echo ""
    log_success "Source set to: $SOURCE_RANGES"
}

confirm_scan() {
    echo ""
    echo -e "${YELLOW}Do you want to proceed with the scan? (y/n)${NC}"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        log_warning "Scan cancelled by user"
        exit 0
    fi
}

build_masscan_command() {
    local cmd="masscan"
    
    # Add targets
    if [[ -f "$TARGETS_FILE" ]] && grep -qv '^#' "$TARGETS_FILE" 2>/dev/null; then
        # Use targets file if it has non-comment entries
        cmd+=" -iL $TARGETS_FILE"
    else
        # Use command line targets
        cmd+=" $CDE_TARGETS"
    fi
    
    # Add port range
    cmd+=" -p$PORT_RANGE"
    
    # Add rate
    cmd+=" --rate $SCAN_RATE"
    
    # Add resume capability
    cmd+=" --resume-index $RESUME_FILE"
    
    # Add output files
    cmd+=" -oJ $JSON_OUTPUT"
    cmd+=" -oG $GNMAP_OUTPUT"
    cmd+=" -oL $LIST_OUTPUT"
    cmd+=" -oX $XML_OUTPUT"
    
    # Add exclude file if exists and has content
    if [[ -f "$EXCLUDE_FILE" ]] && grep -qv '^#' "$EXCLUDE_FILE" 2>/dev/null; then
        cmd+=" --excludefile $EXCLUDE_FILE"
    fi
    
    # Add source IP if specified
    if [[ -n "$SOURCE_IP" ]]; then
        cmd+=" --adapter-ip $SOURCE_IP"
    fi
    
    # Add interface if specified
    if [[ -n "$INTERFACE" ]]; then
        cmd+=" --adapter $INTERFACE"
    fi
    
    # Add banners for service detection
    cmd+=" --banners"
    
    echo "$cmd"
}

check_resume() {
    if [[ -f "$RESUME_FILE" ]]; then
        echo ""
        log_warning "Previous scan state found in: $RESUME_FILE"
        echo -e "${YELLOW}Do you want to resume the previous scan? (y/n)${NC}"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            log_info "Resuming previous scan..."
            masscan --resume "$RESUME_FILE" 2>&1 | tee -a "$CONSOLE_LOG"
            generate_summary
            exit 0
        else
            log_info "Starting fresh scan..."
            rm -f "$RESUME_FILE"
        fi
    fi
}

# Get list of targets from file (excluding comments and empty lines)
get_targets() {
    if [[ -f "$TARGETS_FILE" ]]; then
        grep -v '^#' "$TARGETS_FILE" | grep -v '^$' | grep -v '^[[:space:]]*$'
    else
        echo "$CDE_TARGETS" | tr ',' '\n'
    fi
}

# Build masscan command for a single target
build_single_target_command() {
    local target=$1
    local output_prefix=$2
    local cmd="masscan"
    
    # Add single target
    cmd+=" $target"
    
    # Add port range
    cmd+=" -p$PORT_RANGE"
    
    # Add rate
    cmd+=" --rate $SCAN_RATE"
    
    # Add output files for this target
    cmd+=" -oJ ${output_prefix}.json"
    cmd+=" -oG ${output_prefix}.gnmap"
    cmd+=" -oL ${output_prefix}.txt"
    cmd+=" -oX ${output_prefix}.xml"
    
    # Add exclude file if exists and has content
    if [[ -f "$EXCLUDE_FILE" ]] && grep -qv '^#' "$EXCLUDE_FILE" 2>/dev/null; then
        cmd+=" --excludefile $EXCLUDE_FILE"
    fi
    
    # Add source IP if specified
    if [[ -n "$SOURCE_IP" ]]; then
        cmd+=" --adapter-ip $SOURCE_IP"
    fi
    
    # Add interface if specified
    if [[ -n "$INTERFACE" ]]; then
        cmd+=" --adapter $INTERFACE"
    fi
    
    # Add banners for service detection
    cmd+=" --banners"
    
    echo "$cmd"
}

run_scan() {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                  MASSCAN DISCOVERY PHASE                     ${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Get all targets
    local targets=()
    while IFS= read -r line; do
        targets+=("$line")
    done < <(get_targets)
    
    local total_targets=${#targets[@]}
    
    if [[ $total_targets -eq 0 ]]; then
        log_error "No targets found. Add targets to $TARGETS_FILE"
        exit 1
    fi
    
    log_info "Source Segment: $SOURCE_RANGES"
    log_info "Found $total_targets target(s) to scan"
    echo ""
    
    # Track progress
    local current=0
    local failed_targets=()
    
    # Check for previously completed targets
    if [[ -f "$COMPLETED_FILE" ]]; then
        local prev_count=$(wc -l < "$COMPLETED_FILE" | tr -d ' ')
        log_info "Found previous progress: $prev_count target(s) already completed"
    fi
    
    # Record overall start time
    SCAN_START=$(date +%s)
    echo "Scan started at: $(date)" >> "$CONSOLE_LOG"
    echo "Source Segment: $SOURCE_RANGES" >> "$CONSOLE_LOG"
    
    # Scan each target one by one
    for target in "${targets[@]}"; do
        ((current++))
        
        # Create safe filename from target (replace / and . with _)
        local safe_name="${target//\//_}"
        safe_name="${safe_name//./_}"
        local output_prefix="${PER_TARGET_DIR}/${safe_name}"
        
        # Check if already completed
        if [[ -f "$COMPLETED_FILE" ]] && grep -q "^${target}$" "$COMPLETED_FILE" 2>/dev/null; then
            log_info "[$current/$total_targets] SKIPPED (already completed): $target"
            continue
        fi
        
        echo ""
        echo -e "${CYAN}──────────────────────────────────────────────────────────────${NC}"
        log_info "[$current/$total_targets] Scanning: $target"
        echo -e "${CYAN}──────────────────────────────────────────────────────────────${NC}"
        
        local cmd
        cmd=$(build_single_target_command "$target" "$output_prefix")
        
        echo -e "${YELLOW}Command:${NC} $cmd" | tee -a "$CONSOLE_LOG"
        echo ""
        
        local target_start=$(date +%s)
        
        # Run masscan for this target
        if eval "$cmd" 2>&1 | tee -a "$CONSOLE_LOG"; then
            local target_end=$(date +%s)
            local target_duration=$((target_end - target_start))
            
            # Count results for this target
            local ports_found=0
            if [[ -f "${output_prefix}.txt" ]]; then
                ports_found=$(grep -c "^open" "${output_prefix}.txt" 2>/dev/null || echo "0")
            fi
            
            log_success "[$current/$total_targets] Completed: $target (${target_duration}s, ${ports_found} open ports)"
            
            # Mark as completed
            echo "$target" >> "$COMPLETED_FILE"
            
            # Append to combined results
            if [[ -f "${output_prefix}.txt" ]]; then
                cat "${output_prefix}.txt" >> "$LIST_OUTPUT" 2>/dev/null
            fi
            if [[ -f "${output_prefix}.json" ]]; then
                cat "${output_prefix}.json" >> "$JSON_OUTPUT" 2>/dev/null
            fi
            if [[ -f "${output_prefix}.gnmap" ]]; then
                cat "${output_prefix}.gnmap" >> "$GNMAP_OUTPUT" 2>/dev/null
            fi
        else
            log_error "[$current/$total_targets] Failed or interrupted: $target"
            failed_targets+=("$target")
            
            echo ""
            log_warning "Scan interrupted. Resume with: sudo ./cde_scan.sh --resume"
            log_info "Session: $SESSION_DIR"
            log_info "Progress saved. Completed targets will be skipped on resume."
            
            # Don't exit, continue to summary
            break
        fi
    done
    
    # Calculate total duration
    SCAN_END=$(date +%s)
    SCAN_DURATION=$((SCAN_END - SCAN_START))
    
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                  MASSCAN PHASE COMPLETE                      ${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Count completed
    local completed_count=0
    if [[ -f "$COMPLETED_FILE" ]]; then
        completed_count=$(wc -l < "$COMPLETED_FILE" | tr -d ' ')
    fi
    
    echo -e "  ${GREEN}Completed:${NC}  $completed_count / $total_targets targets"
    echo -e "  ${BLUE}Duration:${NC}   ${SCAN_DURATION} seconds"
    
    if [[ ${#failed_targets[@]} -gt 0 ]]; then
        echo -e "  ${RED}Failed:${NC}     ${#failed_targets[@]} target(s)"
    fi
    
    # Count total open ports
    local total_ports=0
    if [[ -f "$LIST_OUTPUT" ]]; then
        total_ports=$(grep -c "^open" "$LIST_OUTPUT" 2>/dev/null || echo "0")
    fi
    echo -e "  ${YELLOW}Open Ports:${NC} $total_ports"
    echo ""
    
    # Check if all targets are completed
    if [[ $completed_count -eq $total_targets ]]; then
        rm -f "$COMPLETED_FILE"
        log_success "All targets scanned successfully!"
        ALL_SCANS_COMPLETED=true
    else
        echo ""
        log_warning "Scan incomplete. $((total_targets - completed_count)) target(s) remaining."
        log_info "Resume with: sudo ./cde_scan.sh --resume"
        log_info "Session: $SESSION_DIR"
        ALL_SCANS_COMPLETED=false
    fi
}

generate_summary() {
    log_info "Generating scan summary..."
    
    {
        echo "# CDE Segmentation Scan Summary"
        echo ""
        echo "## Scan Details"
        echo ""
        echo "| Property | Value |"
        echo "|----------|-------|"
        echo "| Scan Date | $(date '+%Y-%m-%d %H:%M:%S') |"
        echo "| Target Range | $CDE_TARGETS |"
        echo "| Port Range | $PORT_RANGE |"
        echo "| Scan Rate | $SCAN_RATE pps |"
        echo "| Source IP | ${SOURCE_IP:-Auto-detected} |"
        echo ""
        
        # Count findings
        if [[ -f "$LIST_OUTPUT" ]]; then
            OPEN_PORTS=$(grep -c "^open" "$LIST_OUTPUT" 2>/dev/null || echo "0")
            UNIQUE_HOSTS=$(grep "^open" "$LIST_OUTPUT" 2>/dev/null | awk '{print $4}' | sort -u | wc -l | tr -d ' ')
            
            echo "## Results Overview"
            echo ""
            echo "| Metric | Count |"
            echo "|--------|-------|"
            echo "| Total Open Ports Found | $OPEN_PORTS |"
            echo "| Unique Hosts with Open Ports | $UNIQUE_HOSTS |"
            echo ""
        fi
        
        echo "## Output Files"
        echo ""
        echo "| Format | File |"
        echo "|--------|------|"
        echo "| JSON | \`${JSON_OUTPUT}\` |"
        echo "| Grepable | \`${GNMAP_OUTPUT}\` |"
        echo "| List | \`${LIST_OUTPUT}\` |"
        echo "| XML | \`${XML_OUTPUT}\` |"
        echo "| Console Log | \`${CONSOLE_LOG}\` |"
        echo ""
        
        # Top 10 hosts by open ports
        if [[ -f "$LIST_OUTPUT" ]]; then
            echo "## Top 10 Hosts by Open Ports"
            echo ""
            echo "| Host | Open Ports Count |"
            echo "|------|------------------|"
            grep "^open" "$LIST_OUTPUT" 2>/dev/null | awk '{print $4}' | sort | uniq -c | sort -rn | head -10 | while read count host; do
                echo "| $host | $count |"
            done
            echo ""
            
            echo "## Common Open Ports Found"
            echo ""
            echo "| Port | Count | Common Service |"
            echo "|------|-------|----------------|"
            grep "^open" "$LIST_OUTPUT" 2>/dev/null | awk '{print $3}' | sort | uniq -c | sort -rn | head -20 | while read count port; do
                service=$(get_common_service "$port")
                echo "| $port | $count | $service |"
            done
            echo ""
        fi
        
        echo "## PCI-DSS Compliance Notes"
        echo ""
        echo "> **IMPORTANT**: For PCI-DSS segmentation testing, document:"
        echo "> - Source IP address (NON-CDE segment)"
        echo "> - Target IP ranges (CDE segment)"
        echo "> - Date and time of scan"
        echo "> - All open ports discovered"
        echo "> - Any unexpected connectivity between segments"
        echo ""
        
    } > "$SUMMARY_FILE"
    
    log_success "Summary saved to: $SUMMARY_FILE"
}

get_common_service() {
    local port=$1
    case $port in
        21) echo "FTP" ;;
        22) echo "SSH" ;;
        23) echo "Telnet" ;;
        25) echo "SMTP" ;;
        53) echo "DNS" ;;
        80) echo "HTTP" ;;
        110) echo "POP3" ;;
        135) echo "MS RPC" ;;
        139) echo "NetBIOS" ;;
        143) echo "IMAP" ;;
        443) echo "HTTPS" ;;
        445) echo "SMB" ;;
        993) echo "IMAPS" ;;
        995) echo "POP3S" ;;
        1433) echo "MSSQL" ;;
        1521) echo "Oracle" ;;
        3306) echo "MySQL" ;;
        3389) echo "RDP" ;;
        5432) echo "PostgreSQL" ;;
        5900) echo "VNC" ;;
        6379) echo "Redis" ;;
        8080) echo "HTTP-Alt" ;;
        8443) echo "HTTPS-Alt" ;;
        27017) echo "MongoDB" ;;
        *) echo "-" ;;
    esac
}

#===============================================================================
# PCI-DSS SEGMENTATION REPORT GENERATOR
#===============================================================================

generate_pcidss_report() {
    log_info "Generating PCI-DSS Segmentation Report..."
    
    local REPORT_FILE="${LOG_DIR}/${SCAN_NAME}_pcidss_report.html"
    local SOURCE_RANGES="${SOURCE_RANGES:-$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'NON-CDE Segment')}"
    
    # Get all targets
    local targets=()
    while IFS= read -r line; do
        targets+=("$line")
    done < <(get_targets)
    
    # Start HTML report
    cat > "$REPORT_FILE" << 'HTMLHEADER'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PCI-DSS Segmentation Test Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #1a5f7a 0%, #2d8a6e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            font-size: 28px;
            margin-bottom: 10px;
        }
        .header .subtitle {
            font-size: 14px;
            opacity: 0.9;
        }
        .metadata {
            background: #f8f9fa;
            padding: 20px 30px;
            border-bottom: 1px solid #e0e0e0;
        }
        .metadata-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        .metadata-item {
            display: flex;
            flex-direction: column;
        }
        .metadata-label {
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
            font-weight: 600;
        }
        .metadata-value {
            font-size: 14px;
            color: #333;
            font-weight: 500;
        }
        .content {
            padding: 30px;
        }
        .section-title {
            font-size: 18px;
            color: #1a5f7a;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #1a5f7a;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
        }
        th {
            background: #1a5f7a;
            color: white;
            padding: 12px 15px;
            text-align: left;
            font-weight: 600;
            font-size: 14px;
        }
        td {
            padding: 12px 15px;
            border-bottom: 1px solid #e0e0e0;
            font-size: 13px;
        }
        tr:nth-child(even) {
            background: #f8f9fa;
        }
        tr:hover {
            background: #e8f4f8;
        }
        .status-unreachable {
            color: #2d8a6e;
            font-weight: 600;
        }
        .status-reachable {
            color: #dc3545;
            font-weight: 600;
        }
        .status-partial {
            color: #ffc107;
            font-weight: 600;
        }
        .summary-box {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-item {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #1a5f7a;
        }
        .summary-item.success {
            border-left-color: #2d8a6e;
        }
        .summary-item.warning {
            border-left-color: #ffc107;
        }
        .summary-item.danger {
            border-left-color: #dc3545;
        }
        .summary-number {
            font-size: 32px;
            font-weight: 700;
            color: #1a5f7a;
        }
        .summary-item.success .summary-number {
            color: #2d8a6e;
        }
        .summary-item.danger .summary-number {
            color: #dc3545;
        }
        .summary-label {
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
            margin-top: 5px;
        }
        .footer {
            background: #f8f9fa;
            padding: 20px 30px;
            text-align: center;
            font-size: 12px;
            color: #666;
            border-top: 1px solid #e0e0e0;
        }
        .port-list {
            font-family: monospace;
            font-size: 12px;
            color: #666;
        }
        @media print {
            body { background: white; }
            .container { box-shadow: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>PCI-DSS Segmentation Test Report</h1>
            <div class="subtitle">Network Segmentation Validation - NON-CDE to CDE</div>
        </div>
HTMLHEADER

    # Add metadata section
    cat >> "$REPORT_FILE" << METADATA
        <div class="metadata">
            <div class="metadata-grid">
                <div class="metadata-item">
                    <span class="metadata-label">Scan Date</span>
                    <span class="metadata-value">$(date '+%Y-%m-%d %H:%M:%S')</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Source (Non-CDE)</span>
                    <span class="metadata-value">${SOURCE_RANGES}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Port Range</span>
                    <span class="metadata-value">${PORT_RANGE}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Scan Tool</span>
                    <span class="metadata-value">Masscan + Nmap</span>
                </div>
            </div>
        </div>
        <div class="content">
METADATA

    # Calculate statistics
    local total_targets=${#targets[@]}
    local unreachable_count=0
    local reachable_count=0
    local partial_count=0
    
    # Check each target for open ports
    declare -A target_results
    declare -A target_ports
    
    for target in "${targets[@]}"; do
        local safe_name="${target//\//_}"
        safe_name="${safe_name//./_}"
        local target_file="${LOG_DIR}/per_target/${safe_name}.txt"
        
        if [[ -f "$target_file" ]]; then
            local port_count=$(grep -c "^open" "$target_file" 2>/dev/null || echo "0")
            local ports_list=$(grep "^open" "$target_file" 2>/dev/null | awk '{print $3}' | sort -n | uniq | tr '\n' ',' | sed 's/,$//')
            
            if [[ $port_count -eq 0 ]]; then
                target_results[$target]="unreachable"
                ((unreachable_count++))
            else
                target_results[$target]="reachable"
                target_ports[$target]="$ports_list"
                ((reachable_count++))
            fi
        else
            target_results[$target]="unreachable"
            ((unreachable_count++))
        fi
    done

    # Add summary boxes
    cat >> "$REPORT_FILE" << SUMMARY
            <h2 class="section-title">Executive Summary</h2>
            <div class="summary-box">
                <div class="summary-item">
                    <div class="summary-number">${total_targets}</div>
                    <div class="summary-label">Total CDE Targets</div>
                </div>
                <div class="summary-item success">
                    <div class="summary-number">${unreachable_count}</div>
                    <div class="summary-label">Unreachable (Pass)</div>
                </div>
                <div class="summary-item danger">
                    <div class="summary-number">${reachable_count}</div>
                    <div class="summary-label">Reachable (Fail)</div>
                </div>
            </div>
            
            <h2 class="section-title">Segmentation Test Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Source (Non-CDE Out-Scope)</th>
                        <th>Destination (CDE)</th>
                        <th>Results</th>
                        <th>Open Ports</th>
                    </tr>
                </thead>
                <tbody>
SUMMARY

    # Add each target row
    local first_row=true
    for target in "${targets[@]}"; do
        local status="${target_results[$target]}"
        local ports="${target_ports[$target]:-N/A}"
        local status_class="status-unreachable"
        local status_text="All destination hosts are unreachable."
        
        if [[ "$status" == "reachable" ]]; then
            status_class="status-reachable"
            status_text="⚠️ OPEN PORTS DETECTED"
        fi
        
        if $first_row; then
            cat >> "$REPORT_FILE" << ROW
                    <tr>
                        <td rowspan="${total_targets}">${SOURCE_RANGES}</td>
                        <td>${target}</td>
                        <td class="${status_class}">${status_text}</td>
                        <td class="port-list">${ports}</td>
                    </tr>
ROW
            first_row=false
        else
            cat >> "$REPORT_FILE" << ROW
                    <tr>
                        <td>${target}</td>
                        <td class="${status_class}">${status_text}</td>
                        <td class="port-list">${ports}</td>
                    </tr>
ROW
        fi
    done

    # Close table and add footer
    cat >> "$REPORT_FILE" << 'HTMLFOOTER'
                </tbody>
            </table>
            
            <h2 class="section-title">Compliance Notes</h2>
            <p style="margin-bottom: 15px; line-height: 1.6;">
                This report documents the results of network segmentation testing between Non-CDE (out-of-scope) 
                and CDE (Cardholder Data Environment) network segments as required by PCI-DSS Requirement 11.3.4.
            </p>
            <ul style="margin-left: 20px; line-height: 1.8;">
                <li><strong>Pass (Unreachable):</strong> No network connectivity detected between segments.</li>
                <li><strong>Fail (Reachable):</strong> Open ports detected - segmentation controls may be ineffective.</li>
            </ul>
        </div>
        <div class="footer">
            <p>Generated by CDE Segmentation Scanner | Confidential - For Internal Use Only</p>
        </div>
    </div>
</body>
</html>
HTMLFOOTER

    log_success "PCI-DSS Report saved to: $REPORT_FILE"
    echo -e "  ${YELLOW}Open in browser:${NC} file://$REPORT_FILE"
}

#===============================================================================
# NMAP VERIFICATION FUNCTIONS
#===============================================================================

prepare_nmap_targets() {
    log_info "Preparing targets for nmap verification..."
    
    if [[ ! -f "$LIST_OUTPUT" ]]; then
        log_error "Masscan results not found: $LIST_OUTPUT"
        return 1
    fi
    
    # Extract unique host:port combinations from masscan results
    # Format: host:port1,port2,port3
    local hosts_file="${NMAP_DIR}/hosts_with_ports.txt"
    
    # Create associative array of hosts -> ports
    declare -A host_ports
    
    while IFS= read -r line; do
        if [[ "$line" =~ ^open ]]; then
            local port=$(echo "$line" | awk '{print $3}')
            local host=$(echo "$line" | awk '{print $4}')
            if [[ -n "${host_ports[$host]}" ]]; then
                host_ports[$host]="${host_ports[$host]},$port"
            else
                host_ports[$host]="$port"
            fi
        fi
    done < "$LIST_OUTPUT"
    
    # Write targets file
    > "$NMAP_TARGETS"
    for host in "${!host_ports[@]}"; do
        echo "${host}:${host_ports[$host]}" >> "$NMAP_TARGETS"
    done
    
    local target_count=$(wc -l < "$NMAP_TARGETS" | tr -d ' ')
    log_info "Found $target_count hosts with open ports to verify"
    
    return 0
}

run_nmap_verification() {
    if [[ "$NMAP_VERIFY" != "true" ]]; then
        log_info "Nmap verification is disabled. Skipping..."
        return 0
    fi
    
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                  NMAP VERIFICATION PHASE                     ${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    if ! prepare_nmap_targets; then
        log_warning "Could not prepare nmap targets. Skipping verification."
        return 1
    fi
    
    if [[ ! -s "$NMAP_TARGETS" ]]; then
        log_info "No open ports found by masscan. Nothing to verify."
        return 0
    fi
    
    log_info "Starting nmap verification (this may take a while)..."
    
    # Initialize combined output files
    > "$NMAP_COMBINED"
    > "$VERIFIED_PORTS"
    
    local total_hosts=$(wc -l < "$NMAP_TARGETS" | tr -d ' ')
    local current=0
    local verified_count=0
    local false_positive_count=0
    
    # Process each host with its specific ports
    while IFS= read -r line; do
        ((current++))
        
        local host=$(echo "$line" | cut -d: -f1)
        local ports=$(echo "$line" | cut -d: -f2)
        
        log_info "[$current/$total_hosts] Verifying $host (ports: $ports)..."
        
        local nmap_output="${NMAP_DIR}/nmap_${host//\./_}.txt"
        local nmap_xml="${NMAP_DIR}/nmap_${host//\./_}.xml"
        
        # Run nmap with specific ports
        if nmap $NMAP_OPTIONS -p "$ports" -oN "$nmap_output" -oX "$nmap_xml" "$host" >> "$CONSOLE_LOG" 2>&1; then
            # Parse results and count verified ports
            local verified=$(grep "^[0-9]*/tcp.*open" "$nmap_output" 2>/dev/null | wc -l | tr -d ' ')
            local masscan_count=$(echo "$ports" | tr ',' '\n' | wc -l | tr -d ' ')
            local fp=$((masscan_count - verified))
            
            verified_count=$((verified_count + verified))
            false_positive_count=$((false_positive_count + fp))
            
            # Append to combined output
            echo "=== $host ===" >> "$NMAP_COMBINED"
            cat "$nmap_output" >> "$NMAP_COMBINED"
            echo "" >> "$NMAP_COMBINED"
            
            # Extract verified open ports
            grep "^[0-9]*/tcp.*open" "$nmap_output" 2>/dev/null | while read -r port_line; do
                echo "$host: $port_line" >> "$VERIFIED_PORTS"
            done
            
            if [[ $fp -gt 0 ]]; then
                log_warning "$host: $verified verified, $fp false positives"
            else
                log_success "$host: $verified ports verified"
            fi
        else
            log_warning "Nmap scan failed for $host"
        fi
        
    done < "$NMAP_TARGETS"
    
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                  VERIFICATION SUMMARY                        ${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}Verified Open Ports:${NC}   $verified_count"
    echo -e "  ${YELLOW}False Positives:${NC}       $false_positive_count"
    echo -e "  ${BLUE}Total Hosts Scanned:${NC}   $total_hosts"
    echo ""
    
    log_success "Nmap verification complete. Detailed results in: $NMAP_DIR"
    
    # Update summary with verification results
    append_verification_summary "$verified_count" "$false_positive_count" "$total_hosts"
}

append_verification_summary() {
    local verified=$1
    local false_positives=$2
    local hosts=$3
    
    {
        echo ""
        echo "---"
        echo ""
        echo "## Nmap Verification Results"
        echo ""
        echo "| Metric | Count |"
        echo "|--------|-------|"
        echo "| Verified Open Ports | $verified |"
        echo "| False Positives | $false_positives |"
        echo "| Hosts Verified | $hosts |"
        echo ""
        
        if [[ $false_positives -gt 0 ]]; then
            local accuracy=$(echo "scale=1; ($verified / ($verified + $false_positives)) * 100" | bc 2>/dev/null || echo "N/A")
            echo "> **Accuracy Rate**: ${accuracy}%"
            echo ""
        fi
        
        echo "### Verified Open Ports by Host"
        echo ""
        echo "\`\`\`"
        if [[ -f "$VERIFIED_PORTS" ]]; then
            cat "$VERIFIED_PORTS"
        else
            echo "No verified ports found."
        fi
        echo "\`\`\`"
        echo ""
        
        echo "### Nmap Verification Files"
        echo ""
        echo "| File | Description |"
        echo "|------|-------------|"
        echo "| \`$NMAP_COMBINED\` | Combined nmap output |"
        echo "| \`$VERIFIED_PORTS\` | List of verified ports |"
        echo "| \`$NMAP_DIR/*.xml\` | Individual XML reports |"
        echo ""
        
    } >> "$SUMMARY_FILE"
}

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --resume          Resume a previous interrupted scan"
    echo "  --targets FILE    Use custom targets file"
    echo "  --exclude FILE    Use custom exclude file"
    echo "  --rate RATE       Set scan rate (pps)"
    echo "  --ports PORTS     Set port range (e.g., 0-65535)"
    echo "  --src IP          Set source IP address"
    echo "  --source-ranges   Set source ranges for PCI-DSS report (e.g., '10.240.32.0/21')"
    echo "  --no-nmap         Skip nmap verification phase"
    echo "  --nmap-only       Run only nmap verification on existing masscan results"
    echo "  --nmap-opts OPTS  Custom nmap options (default: -sV -sC)"
    echo "  --help            Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  CDE_TARGETS       Target IP ranges (comma-separated)"
    echo "  PORT_RANGE        Port range to scan"
    echo "  SCAN_RATE         Scan rate in packets per second"
    echo "  SOURCE_IP         Source IP address"
    echo "  SOURCE_RANGES     Source ranges for PCI-DSS report"
    echo "  INTERFACE         Network interface to use"
    echo "  NMAP_VERIFY       Enable/disable nmap verification (true/false)"
    echo "  NMAP_OPTIONS      Custom nmap scan options"
    echo ""
    echo "Examples:"
    echo "  sudo ./cde_scan.sh                          # Full scan with nmap verification"
    echo "  sudo ./cde_scan.sh --resume                 # Resume interrupted scan"
    echo "  sudo ./cde_scan.sh --no-nmap                # Skip nmap verification"
    echo "  sudo ./cde_scan.sh --nmap-only              # Only run nmap on existing results"
    echo "  sudo SOURCE_RANGES='10.240.32.0/21' ./cde_scan.sh"
    echo "  sudo ./cde_scan.sh --rate 500 --ports 1-1024"
}

#===============================================================================
# ARGUMENT PARSING
#===============================================================================

RESUME_MODE=false
NMAP_ONLY_MODE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --resume)
            RESUME_MODE=true
            shift
            ;;
        --targets)
            TARGETS_FILE="$2"
            shift 2
            ;;
        --exclude)
            EXCLUDE_FILE="$2"
            shift 2
            ;;
        --rate)
            SCAN_RATE="$2"
            shift 2
            ;;
        --ports)
            PORT_RANGE="$2"
            shift 2
            ;;
        --src)
            SOURCE_IP="$2"
            shift 2
            ;;
        --source-ranges)
            SOURCE_RANGES="$2"
            shift 2
            ;;
        --no-nmap)
            NMAP_VERIFY="false"
            shift
            ;;
        --nmap-only)
            NMAP_ONLY_MODE=true
            shift
            ;;
        --nmap-opts)
            NMAP_OPTIONS="$2"
            shift 2
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

#===============================================================================
# MAIN EXECUTION
#===============================================================================

main() {
    print_banner
    check_root
    check_masscan
    check_nmap
    setup_directories
    create_default_configs
    
    if $NMAP_ONLY_MODE; then
        # Only run nmap verification on existing results
        log_info "Running nmap-only verification mode..."
        
        # Find the most recent masscan results
        local latest_results=$(find "$LOG_DIR" -name "cde_scan_*.txt" -type f 2>/dev/null | sort -r | head -1)
        
        if [[ -z "$latest_results" ]]; then
            log_error "No previous masscan results found in: $LOG_DIR"
            log_info "Run a full scan first: sudo ./cde_scan.sh"
            exit 1
        fi
        
        LIST_OUTPUT="$latest_results"
        SCAN_NAME=$(basename "$latest_results" .txt)
        NMAP_DIR="${LOG_DIR}/nmap_verification"
        NMAP_TARGETS="${NMAP_DIR}/targets_to_verify.txt"
        NMAP_COMBINED="${NMAP_DIR}/nmap_combined.txt"
        VERIFIED_PORTS="${NMAP_DIR}/verified_ports.txt"
        SUMMARY_FILE="${LOG_DIR}/${SCAN_NAME}_summary.md"
        
        mkdir -p "$NMAP_DIR"
        
        log_info "Using masscan results: $LIST_OUTPUT"
        run_nmap_verification
        ALL_SCANS_COMPLETED=true
        
    elif $RESUME_MODE; then
        # List available sessions to resume
        echo ""
        echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
        echo -e "${CYAN}                    AVAILABLE SESSIONS                        ${NC}"
        echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
        echo ""
        
        local sessions_dir="${LOG_DIR}/sessions"
        if [[ -d "$sessions_dir" ]]; then
            local session_count=0
            for session in "$sessions_dir"/*/; do
                if [[ -d "$session" ]]; then
                    ((session_count++))
                    local source_file="${session}.source_ranges"
                    local completed_file="${session}.completed_targets"
                    local source_name="Unknown"
                    local progress="0"
                    
                    if [[ -f "$source_file" ]]; then
                        source_name=$(cat "$source_file")
                    fi
                    if [[ -f "$completed_file" ]]; then
                        progress=$(wc -l < "$completed_file" | tr -d ' ')
                    fi
                    
                    echo -e "  ${YELLOW}[$session_count]${NC} $source_name (${progress} targets completed)"
                fi
            done
            
            if [[ $session_count -eq 0 ]]; then
                log_error "No sessions found to resume."
                log_info "Run 'sudo ./cde_scan.sh' to start a new scan."
                exit 1
            fi
            
            echo ""
            prompt_source_ranges
            setup_session_dirs
            
            if [[ -f "$COMPLETED_FILE" ]]; then
                local completed_count=$(wc -l < "$COMPLETED_FILE" | tr -d ' ')
                log_info "Resuming session: $SOURCE_RANGES"
                log_info "Progress: $completed_count target(s) already completed"
                
                show_config
                run_scan
                
                if [[ "$ALL_SCANS_COMPLETED" == "true" ]]; then
                    generate_summary
                    if [[ "$NMAP_VERIFY" == "true" ]]; then
                        run_nmap_verification
                    fi
                fi
            else
                log_info "No progress found for this source segment. Starting fresh."
                show_config
                confirm_scan
                run_scan
                
                if [[ "$ALL_SCANS_COMPLETED" == "true" ]]; then
                    generate_summary
                    if [[ "$NMAP_VERIFY" == "true" ]]; then
                        run_nmap_verification
                    fi
                fi
            fi
        else
            log_error "No sessions found. Run 'sudo ./cde_scan.sh' to start a new scan."
            exit 1
        fi
    else
        # STEP 1: Prompt for source ranges
        prompt_source_ranges
        
        # STEP 2: Setup session directories
        setup_session_dirs
        
        # STEP 3: Show configuration and confirm
        show_config
        confirm_scan
        
        # STEP 4: Run scan (will set ALL_SCANS_COMPLETED)
        run_scan
        
        # STEP 5: If all done, generate summary and reports
        if [[ "$ALL_SCANS_COMPLETED" == "true" ]]; then
            generate_summary
            
            if [[ "$NMAP_VERIFY" == "true" ]]; then
                run_nmap_verification
            fi
        fi
    fi
    
    # STEP 5: Generate reports ONLY if all scans completed
    if [[ "$ALL_SCANS_COMPLETED" == "true" ]]; then
        generate_pcidss_report
        
        echo ""
        echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
        echo -e "${CYAN}                    SCAN COMPLETE                             ${NC}"
        echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
        echo ""
        log_success "All scans completed! Reports generated."
        echo ""
        echo -e "  ${YELLOW}Summary Report:${NC}  $SUMMARY_FILE"
        echo -e "  ${YELLOW}PCI-DSS Report:${NC}  ${LOG_DIR}/${SCAN_NAME}_pcidss_report.html"
        if [[ "$NMAP_VERIFY" == "true" ]]; then
            echo -e "  ${YELLOW}Nmap Results:${NC}    $NMAP_DIR"
        fi
        echo ""
        echo -e "  ${GREEN}Open the PCI-DSS report in your browser:${NC}"
        echo -e "  file://${LOG_DIR}/${SCAN_NAME}_pcidss_report.html"
        echo ""
    else
        echo ""
        echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
        echo -e "${CYAN}                    SCAN INCOMPLETE                           ${NC}"
        echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
        echo ""
        log_info "Resume the scan with: sudo ./cde_scan.sh"
        log_info "Report will be generated after all targets are scanned."
        echo ""
    fi
}

# Initialize global variable
ALL_SCANS_COMPLETED=false

main "$@"
