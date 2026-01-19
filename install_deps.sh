#!/bin/bash
#
# CDE Scanner Dependency Installer
# Auto-detects OS and installs masscan + nmap
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    elif [[ -f /etc/redhat-release ]]; then
        echo "redhat"
    elif [[ -f /etc/arch-release ]]; then
        echo "arch"
    elif [[ -f /etc/alpine-release ]]; then
        echo "alpine"
    else
        echo "unknown"
    fi
}

# Check if command exists
check_cmd() {
    command -v "$1" &> /dev/null
}

# Install for macOS
install_macos() {
    if ! check_cmd brew; then
        log_error "Homebrew not installed. Install from https://brew.sh"
        exit 1
    fi
    
    log_info "Installing via Homebrew..."
    [[ "$1" == "masscan" ]] && brew install masscan
    [[ "$1" == "nmap" ]] && brew install nmap
}

# Install for Debian/Ubuntu
install_debian() {
    log_info "Installing via apt..."
    sudo apt-get update -qq
    sudo apt-get install -y "$1"
}

# Install for RHEL/CentOS/Fedora
install_redhat() {
    log_info "Installing via dnf/yum..."
    if check_cmd dnf; then
        sudo dnf install -y "$1"
    else
        sudo yum install -y "$1"
    fi
}

# Install for Arch
install_arch() {
    log_info "Installing via pacman..."
    sudo pacman -S --noconfirm "$1"
}

# Install for Alpine
install_alpine() {
    log_info "Installing via apk..."
    sudo apk add "$1"
}

# Main install function
install_tool() {
    local tool=$1
    local os=$2
    
    case $os in
        macos)  install_macos "$tool" ;;
        debian) install_debian "$tool" ;;
        redhat) install_redhat "$tool" ;;
        arch)   install_arch "$tool" ;;
        alpine) install_alpine "$tool" ;;
        *)
            log_error "Unsupported OS. Please install $tool manually."
            return 1
            ;;
    esac
}

# Main
main() {
    echo "=================================="
    echo " CDE Scanner Dependency Installer"
    echo "=================================="
    echo
    
    OS=$(detect_os)
    log_info "Detected OS: $OS"
    echo
    
    TOOLS=("masscan" "nmap")
    MISSING=()
    
    # Check what's missing
    for tool in "${TOOLS[@]}"; do
        if check_cmd "$tool"; then
            log_success "$tool is installed"
        else
            log_warn "$tool is NOT installed"
            MISSING+=("$tool")
        fi
    done
    
    echo
    
    # Install missing tools
    if [[ ${#MISSING[@]} -eq 0 ]]; then
        log_success "All dependencies are installed!"
        exit 0
    fi
    
    log_info "Installing missing tools: ${MISSING[*]}"
    echo
    
    for tool in "${MISSING[@]}"; do
        log_info "Installing $tool..."
        if install_tool "$tool" "$OS"; then
            log_success "$tool installed successfully"
        else
            log_error "Failed to install $tool"
        fi
        echo
    done
    
    # Verify
    echo "=================================="
    echo " Verification"
    echo "=================================="
    for tool in "${TOOLS[@]}"; do
        if check_cmd "$tool"; then
            log_success "$tool: $(command -v $tool)"
        else
            log_error "$tool: NOT FOUND"
        fi
    done
}

main "$@"
