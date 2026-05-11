#!/bin/bash
#===============================================================================
# deploy-configs.sh
# Author: Network Security Sensor Project
# Usage: sudo ./deploy-configs.sh
#===============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIGS_DIR="${SCRIPT_DIR}/../../configs/suricata"

# System paths
SURICATA_CONFIG_DIR="/etc/suricata"
SURICATA_RULES_DIR="/etc/suricata/rules"

# Report arrays
declare -a COPY_SUCCESS=()
declare -a COPY_FAILED=()

#===============================================================================
# Helper Functions
#===============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo ""
    echo "=========================================="
    echo -e "${BLUE}$1${NC}"
    echo "=========================================="
}

#===============================================================================
# Check Root
#===============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Script này cần chạy với quyền root (sudo)"
        exit 1
    fi
}

#===============================================================================
# 1️⃣ Check Installation
#===============================================================================

check_suricata_installed() {
    print_header "Kiểm tra Suricata"
    
    if command -v suricata &> /dev/null; then
        SURICATA_VERSION=$(suricata --build-info | grep -oP 'Suricata version \K[\d.]+' || suricata -V 2>&1 | grep -oP '[\d.]+' | head -1)
        log_success "Suricata đã cài đặt: version ${SURICATA_VERSION}"
        return 0
    else
        log_error "Suricata chưa được cài đặt!"
        return 1
    fi
}


check_config_files() {
    print_header "Kiểm tra file cấu hình trong configs/suricata/"
    
    if [[ ! -d "${CONFIGS_DIR}" ]]; then
        log_warning "Thư mục configs/suricata/ không tồn tại. Đang tạo..."
        mkdir -p "${CONFIGS_DIR}"
    fi
    
    # Check each config file
    local files_found=0
    
    if [[ -f "${CONFIGS_DIR}/suricata.yaml" ]]; then
        log_success "Tìm thấy: configs/suricata/suricata.yaml"
        ((files_found++))
    else
        log_warning "Không tìm thấy: configs/suricata/suricata.yaml"
    fi
    
    if [[ -f "${CONFIGS_DIR}/custom.rules" ]]; then
        log_success "Tìm thấy: configs/suricata/custom.rules"
        ((files_found++))
    else
        log_warning "Không tìm thấy: configs/suricata/custom.rules"
    fi
    
    
    if [[ $files_found -eq 0 ]]; then
        log_error "Không tìm thấy file cấu hình nào trong configs/suricata/"
        return 1
    fi
    
    return 0
}

#===============================================================================
# 2️⃣ & 3️⃣ Copy Config Files
#===============================================================================

copy_file() {
    local src="$1"
    local dest="$2"
    local desc="$3"
    
    if [[ -f "$src" ]]; then
        # Create destination directory if not exists
        local dest_dir=$(dirname "$dest")
        if [[ ! -d "$dest_dir" ]]; then
            log_info "Tạo thư mục: $dest_dir"
            mkdir -p "$dest_dir"
        fi
        
        # Backup existing file
        if [[ -f "$dest" ]]; then
            cp "$dest" "${dest}.backup.$(date +%Y%m%d_%H%M%S)"
            log_info "Đã backup file cũ: ${dest}.backup.*"
        fi
        
        # Copy file
        if cp "$src" "$dest"; then
            log_success "Đã copy: $desc"
            COPY_SUCCESS+=("$desc")
            return 0
        else
            log_error "Không thể copy: $desc"
            COPY_FAILED+=("$desc")
            return 1
        fi
    else
        log_warning "File không tồn tại, bỏ qua: $src"
        return 2
    fi
}

copy_directory() {
    local src="$1"
    local dest="$2"
    local desc="$3"
    
    if [[ -d "$src" ]]; then
        # Create destination directory if not exists
        if [[ ! -d "$dest" ]]; then
            log_info "Tạo thư mục: $dest"
            mkdir -p "$dest"
        fi
        
        # Copy directory contents
        if cp -r "$src"/* "$dest"/ 2>/dev/null; then
            log_success "Đã copy: $desc"
            COPY_SUCCESS+=("$desc")
            return 0
        else
            log_error "Không thể copy: $desc"
            COPY_FAILED+=("$desc")
            return 1
        fi
    else
        log_warning "Thư mục không tồn tại, bỏ qua: $src"
        return 2
    fi
}

deploy_suricata_configs() {
    print_header "Deploy Suricata Configs"
    
    # Create directories
    mkdir -p "${SURICATA_CONFIG_DIR}"
    mkdir -p "${SURICATA_RULES_DIR}"
    
    # Copy suricata.yaml
    copy_file "${CONFIGS_DIR}/suricata.yaml" \
              "${SURICATA_CONFIG_DIR}/suricata.yaml" \
              "suricata.yaml → ${SURICATA_CONFIG_DIR}/"
    
    # Copy custom.rules
    copy_file "${CONFIGS_DIR}/custom.rules" \
              "${SURICATA_RULES_DIR}/custom.rules" \
              "custom.rules → ${SURICATA_RULES_DIR}/"
    
    # Set permissions
    log_info "Đặt permissions cho Suricata configs..."
    chmod 644 "${SURICATA_CONFIG_DIR}/suricata.yaml" 2>/dev/null || true
    chmod 644 "${SURICATA_RULES_DIR}/custom.rules" 2>/dev/null || true
    chmod 755 "${SURICATA_CONFIG_DIR}" 2>/dev/null || true
    chmod 755 "${SURICATA_RULES_DIR}" 2>/dev/null || true
    chown -R suricata:suricata "${SURICATA_CONFIG_DIR}" 2>/dev/null || true
}


#===============================================================================
# Restart Services
#===============================================================================

restart_suricata() {
    print_header "Restart Suricata"
    
    if systemctl is-active --quiet suricata; then
        log_info "Đang restart Suricata..."
        if systemctl restart suricata; then
            sleep 3
            if systemctl is-active --quiet suricata; then
                log_success "Suricata đã restart thành công"
                return 0
            else
                log_error "Suricata không khởi động được sau restart"
                return 1
            fi
        else
            log_error "Không thể restart Suricata"
            return 1
        fi
    else
        log_info "Đang start Suricata..."
        if systemctl start suricata; then
            sleep 3
            log_success "Suricata đã start thành công"
            return 0
        else
            log_error "Không thể start Suricata"
            return 1
        fi
    fi
}


#===============================================================================
# 4️⃣ Generate Report
#===============================================================================

generate_report() {
    print_header "📋 BÁO CÁO DEPLOY"
    
    echo ""
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│                    KẾT QUẢ COPY FILES                       │"
    echo "├─────────────────────────────────────────────────────────────┤"
    
    if [[ ${#COPY_SUCCESS[@]} -gt 0 ]]; then
        echo -e "│ ${GREEN}✅ Thành công:${NC}                                              │"
        for item in "${COPY_SUCCESS[@]}"; do
            printf "│   %-57s │\n" "$item"
        done
    fi
    
    if [[ ${#COPY_FAILED[@]} -gt 0 ]]; then
        echo -e "│ ${RED}❌ Thất bại:${NC}                                                │"
        for item in "${COPY_FAILED[@]}"; do
            printf "│   %-57s │\n" "$item"
        done
    fi
    
    if [[ ${#COPY_SUCCESS[@]} -eq 0 ]] && [[ ${#COPY_FAILED[@]} -eq 0 ]]; then
        echo "│   Không có file nào được copy                              │"
    fi
    
    echo "├─────────────────────────────────────────────────────────────┤"
    echo "│                    TRẠNG THÁI DỊCH VỤ                       │"
    echo "├─────────────────────────────────────────────────────────────┤"
    
    # Suricata status
    if systemctl is-active --quiet suricata 2>/dev/null; then
        echo -e "│ Suricata:  ${GREEN}✅ RUNNING${NC}                                       │"
    else
        echo -e "│ Suricata:  ${RED}❌ STOPPED${NC}                                       │"
    fi
    
    
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    
    # Summary
    local total_success=${#COPY_SUCCESS[@]}
    local total_failed=${#COPY_FAILED[@]}
    
    if [[ $total_failed -eq 0 ]] && [[ $total_success -gt 0 ]]; then
        log_success "Deploy hoàn tất! $total_success file(s) đã được copy thành công."
    elif [[ $total_failed -gt 0 ]]; then
        log_warning "Deploy hoàn tất với lỗi. Thành công: $total_success, Thất bại: $total_failed"
    else
        log_warning "Không có file nào được deploy."
    fi
}

#===============================================================================
# Main
#===============================================================================

main() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║        DEPLOY SURICATA CONFIGURATIONS                         ║"
    echo "║        Network Security Sensor Project                        ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
    
    # Check root
    check_root
    
    # Check installations
    SURICATA_INSTALLED=false
    
    if check_suricata_installed; then
        SURICATA_INSTALLED=true
    fi
    
    
    # Check config files
    if ! check_config_files; then
        log_error "Không thể tiếp tục vì không có file cấu hình"
        exit 1
    fi
    
    # Deploy configs
    if [[ "$SURICATA_INSTALLED" == "true" ]]; then
        deploy_suricata_configs
    else
        log_warning "Bỏ qua deploy Suricata configs vì Suricata chưa cài"
    fi
    
    
    # Restart services
    if [[ "$SURICATA_INSTALLED" == "true" ]]; then
        restart_suricata || true
    fi
    
    
    # Generate report
    generate_report
}

# Run main function
main "$@"
