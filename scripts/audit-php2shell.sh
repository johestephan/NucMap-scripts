#!/usr/bin/env bash
# ==============================================================================
# audit-php2shell.sh
# Audits local and remote PHP installations for PHP2Shell vulnerabilities
# (CVE-2026-109618 and CVE-2026-109619).
# 
# PHP2Shell refers to two critical remote code execution vulnerabilities:
# - CVE-2026-109618: OOM error handling via longjmp() leaves request memory
#   uninitialized, allowing RCE using OOM triggers.
# - CVE-2026-109619: Fatal error handling via longjmp() leaves global memory
#   pointing to freed regions, enabling arbitrary code execution.
# 
# Both rated 9.2 (CVSS 4.0) and affect PHP 8.0.x through 8.3.x.
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

# Vulnerable version ranges
# PHP 8.3.0-8.3.28 are vulnerable
# PHP 8.2.0-8.2.56 are vulnerable
# PHP 8.1.0-8.1.91 are vulnerable
# PHP 8.0.0-8.0.112 are vulnerable

# Patched versions
PATCHED_VERSIONS=(
  "8.3.29" "8.3.30" "8.3.31" "8.4.0"
  "8.2.57" "8.2.58" "8.2.59"
  "8.1.92" "8.1.93" "8.1.94"
  "8.0.113" "8.0.114" "8.0.115"
)

# Vulnerable version patterns
VULNERABLE_PATTERNS=(
  "8\.3\.[0-9]" "8\.3\.[0-9][0-9]" "8\.3\.2[0-8]"
  "8\.2\.[0-9]" "8\.2\.[0-9][0-9]" "8\.2\.5[0-6]"
  "8\.1\.[0-9]" "8\.1\.[0-9][0-9]" "8\.1\.9[0-1]"
  "8\.0\.[0-9]" "8\.0\.[0-9][0-9]" "8\.0\.1[0-9][0-9]" "8\.0\.11[0-2]"
)

# Function to check if version is vulnerable
is_vulnerable() {
  local version="$1"
  
  # Check if it's a patched version
  for patched in "${PATCHED_VERSIONS[@]}"; do
    if [[ "$version" == "$patched" ]]; then
      return 1  # Not vulnerable (0 = vulnerable, 1 = not vulnerable in bash)
    fi
  done
  
  # Check against vulnerable patterns
  for pattern in "${VULNERABLE_PATTERNS[@]}"; do
    if [[ "$version" =~ ^$pattern$ ]]; then
      return 0  # Vulnerable
    fi
  done
  
  # Check if version is in 8.x range but not matching patterns
  if [[ "$version" =~ ^8\.[0-3]\. ]]; then
    # Extract major.minor.patch
    local major_minor_patch="$version"
    local major="${major_minor_patch%%.*}"
    local rest="${major_minor_patch#*.}"
    local minor="${rest%%.*}"
    local patch="${rest#*.}"
    
    case "$major.$minor" in
      "8.3")
        if [[ "$patch" -le 28 ]]; then
          return 0
        fi
        ;;
      "8.2")
        if [[ "$patch" -le 56 ]]; then
          return 0
        fi
        ;;
      "8.1")
        if [[ "$patch" -le 91 ]]; then
          return 0
        fi
        ;;
      "8.0")
        if [[ "$patch" -le 112 ]]; then
          return 0
        fi
        ;;
    esac
  fi
  
  return 1  # Not vulnerable
}

# Function to parse PHP version from string
parse_php_version() {
  local input="$1"
  local version=""
  
  # Try to extract version number
  version=$(echo "$input" | grep -oP 'PHP[/\s]*\K[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  if [[ -n "$version" ]]; then
    echo "$version"
    return
  fi
  
  # Try without PHP prefix
  version=$(echo "$input" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  if [[ -n "$version" ]]; then
    echo "$version"
    return
  fi
  
  echo ""
}

# Function to check local PHP installation
check_local_php() {
  echo -e "${CYAN}[*] Checking local PHP installations...${NC}"
  echo ""
  
  local found_vulnerable=0
  local checked_count=0
  
  # Check PHP CLI
  if command -v php &>/dev/null; then
    checked_count=$((checked_count + 1))
    local version_output=$(php -v 2>/dev/null | head -1)
    local version=$(parse_php_version "$version_output")
    
    if [[ -n "$version" ]]; then
      echo -e "  PHP CLI: $version_output"
      if is_vulnerable "$version"; then
        echo -e "    ${RED}[!] VULNERABLE to PHP2Shell (CVE-2026-109618, CVE-2026-109619)${NC}"
        found_vulnerable=$((found_vulnerable + 1))
      else
        echo -e "    ${GREEN}[+] NOT VULNERABLE${NC}"
      fi
    else
      echo -e "  PHP CLI: $version_output"
      echo -e "    ${YELLOW}[?] Could not parse version${NC}"
    fi
  fi
  
  # Check PHP-FPM
  if command -v php-fpm &>/dev/null; then
    checked_count=$((checked_count + 1))
    local version_output=$(php-fpm -v 2>/dev/null | head -1)
    local version=$(parse_php_version "$version_output")
    
    if [[ -n "$version" ]]; then
      echo -e "  PHP-FPM: $version_output"
      if is_vulnerable "$version"; then
        echo -e "    ${RED}[!] VULNERABLE to PHP2Shell (CVE-2026-109618, CVE-2026-109619)${NC}"
        found_vulnerable=$((found_vulnerable + 1))
      else
        echo -e "    ${GREEN}[+] NOT VULNERABLE${NC}"
      fi
    else
      echo -e "  PHP-FPM: $version_output"
      echo -e "    ${YELLOW}[?] Could not parse version${NC}"
    fi
  fi
  
  # Check for PHP modules
  if command -v php &>/dev/null; then
    echo ""
    echo -e "  ${BLUE}[i] Checking loaded PHP modules...${NC}"
    php -m 2>/dev/null | grep -iE 'fpm|cgi|apache|mod_php' || true
  fi
  
  echo ""
  return $found_vulnerable
}

# Function to check PHP packages in package manager
check_packages() {
  echo -e "${CYAN}[*] Checking installed PHP packages...${NC}"
  echo ""
  
  local found_vulnerable=0
  local checked_count=0
  
  # Check for different package managers
  if command -v dpkg &>/dev/null; then
    # Debian/Ubuntu
    local packages=$(dpkg -l | grep -i php | grep -v "^ii" | awk '{print $3}' | sort -u)
    for pkg in $packages; do
      checked_count=$((checked_count + 1))
      local version=$(dpkg -s "$pkg" 2>/dev/null | grep Version | awk '{print $2}' | cut -d'-' -f1)
      if [[ -n "$version" ]]; then
        version=$(echo "$version" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        if [[ -n "$version" ]]; then
          echo -e "  $pkg: $version"
          if is_vulnerable "$version"; then
            echo -e "    ${RED}[!] VULNERABLE to PHP2Shell${NC}"
            found_vulnerable=$((found_vulnerable + 1))
          else
            echo -e "    ${GREEN}[+] NOT VULNERABLE${NC}"
          fi
        fi
      fi
    done
  elif command -v rpm &>/dev/null; then
    # RHEL/CentOS/Fedora
    local packages=$(rpm -qa | grep -i php | sort -u)
    for pkg in $packages; do
      checked_count=$((checked_count + 1))
      local version=$(rpm -q "$pkg" --queryformat '%{VERSION}' 2>/dev/null | head -1)
      if [[ -n "$version" ]]; then
        version=$(echo "$version" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        if [[ -n "$version" ]]; then
          echo -e "  $pkg: $version"
          if is_vulnerable "$version"; then
            echo -e "    ${RED}[!] VULNERABLE to PHP2Shell${NC}"
            found_vulnerable=$((found_vulnerable + 1))
          else
            echo -e "    ${GREEN}[+] NOT VULNERABLE${NC}"
          fi
        fi
      fi
    done
  elif command -v pacman &>/dev/null; then
    # Arch Linux
    local packages=$(pacman -Q | grep -i php | awk '{print $1}' | sort -u)
    for pkg in $packages; do
      checked_count=$((checked_count + 1))
      local version=$(pacman -Q "$pkg" | awk '{print $2}')
      if [[ -n "$version" ]]; then
        version=$(echo "$version" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        if [[ -n "$version" ]]; then
          echo -e "  $pkg: $version"
          if is_vulnerable "$version"; then
            echo -e "    ${RED}[!] VULNERABLE to PHP2Shell${NC}"
            found_vulnerable=$((found_vulnerable + 1))
          else
            echo -e "    ${GREEN}[+] NOT VULNERABLE${NC}"
          fi
        fi
      fi
    done
  fi
  
  echo ""
  return $found_vulnerable
}

# Function to check web server PHP version via curl
check_remote() {
  local url="$1"
  echo -e "${CYAN}[*] Checking remote URL: $url${NC}"
  echo ""
  
  local found_vulnerable=0
  
  # Try to get version from headers
  local headers
  headers=$(curl -sI -A "PHP2Shell-Scanner/1.0" "$url" -m 10 2>/dev/null || true)
  
  if [[ -n "$headers" ]]; then
    echo -e "  ${BLUE}[i] Headers:${NC}"
    echo "$headers" | grep -iE 'X-Powered-By|Server' | sed 's/^/    /'
    
    # Extract PHP version from headers
    local version=$(echo "$headers" | grep -iE 'X-Powered-By|Server' | grep -oP 'PHP[/\s]*\K[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [[ -n "$version" ]]; then
      echo -e "  Detected PHP version: $version"
      if is_vulnerable "$version"; then
        echo -e "    ${RED}[!] VULNERABLE to PHP2Shell (CVE-2026-109618, CVE-2026-109619)${NC}"
        found_vulnerable=1
      else
        echo -e "    ${GREEN}[+] NOT VULNERABLE${NC}"
      fi
    fi
  fi
  
  # Try phpinfo pages
  local phpinfo_pages=("/phpinfo.php" "/info.php" "/php_info.php" "/test.php")
  for page in "${phpinfo_pages[@]}"; do
    local page_url="${url%/}${page}"
    local response
    response=$(curl -s "$page_url" -A "PHP2Shell-Scanner/1.0" -m 5 2>/dev/null || true)
    
    if [[ -n "$response" ]]; then
      local version=$(echo "$response" | grep -oP 'PHP Version[^>]*>\K[0-9]+\.[0-9]+\.[0-9]+' | head -1)
      if [[ -n "$version" ]]; then
        echo -e "  Detected PHP version in $page: $version"
        if is_vulnerable "$version"; then
          echo -e "    ${RED}[!] VULNERABLE to PHP2Shell (CVE-2026-109618, CVE-2026-109619)${NC}"
          found_vulnerable=1
        else
          echo -e "    ${GREEN}[+] NOT VULNERABLE${NC}"
        fi
        break
      fi
    fi
  done
  
  echo ""
  return $found_vulnerable
}

# Function to check directory for PHP files
scan_directory() {
  local dir="$1"
  echo -e "${CYAN}[*] Scanning directory: $dir${NC}"
  echo ""
  
  local found_vulnerable=0
  local found_files=0
  
  if [[ ! -d "$dir" ]]; then
    echo -e "  ${YELLOW}[!] Directory does not exist: $dir${NC}"
    echo ""
    return 0
  fi
  
  # Find PHP files
  while IFS= read -r -d '' file; do
    found_files=$((found_files + 1))
    
    # Check if it's a shebang file
    local first_line=$(head -1 "$file" 2>/dev/null || true)
    if [[ "$first_line" =~ ^#!/.*php ]]; then
      echo -e "  ${BLUE}[i] Shebang PHP file: $file${NC}"
      local version=$(grep -oP 'php[0-9]+\.[0-9]+' "$first_line" 2>/dev/null | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
      if [[ -n "$version" && "$version" != "" ]]; then
        if is_vulnerable "$version"; then
          echo -e "    ${RED}[!] VULNERABLE to PHP2Shell${NC}"
          found_vulnerable=$((found_vulnerable + 1))
        else
          echo -e "    ${GREEN}[+] NOT VULNERABLE${NC}"
        fi
      fi
      continue
    fi
    
    # Try to extract version from comments or config
    local version=$(grep -oP 'PHP[\s/]*[0-9]+\.[0-9]+\.[0-9]+' "$file" 2>/dev/null | head -1 || true)
    if [[ -n "$version" ]]; then
      version=$(echo "$version" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
      if [[ -n "$version" ]]; then
        echo -e "  ${BLUE}[i] PHP version reference in: $file${NC}"
        echo -e "    Version: $version"
        if is_vulnerable "$version"; then
          echo -e "    ${RED}[!] VULNERABLE to PHP2Shell${NC}"
          found_vulnerable=$((found_vulnerable + 1))
        else
          echo -e "    ${GREEN}[+] NOT VULNERABLE${NC}"
        fi
      fi
    fi
  done < <(find "$dir" -type f \( -name "*.php" -o -name "*.php5" -o -name "*.php7" -o -name "*.php8" -o -name "*.phtml" \) -print0 2>/dev/null)
  
  echo -e "  Scanned $found_files PHP files"
  echo ""
  return $found_vulnerable
}

# Main execution
main() {
  echo ""
  echo -e "${BLUE}================================================================================${NC}"
  echo -e "  PHP2Shell Vulnerability Auditor (CVE-2026-109618, CVE-2026-109619)"
  echo -e "  Critical RCE vulnerabilities in PHP (CVSS 9.2)"
  echo -e "${BLUE}================================================================================${NC}"
  echo ""
  
  local total_vulnerable=0
  
  # Check if arguments are provided
  if [[ $# -gt 0 ]]; then
    for arg in "$@"; do
      # Check if it's a URL
      if [[ "$arg" =~ ^https?:// ]]; then
        if check_remote "$arg"; then
          total_vulnerable=$((total_vulnerable + 1))
        fi
      # Check if it's a directory
      elif [[ -d "$arg" ]]; then
        if scan_directory "$arg"; then
          total_vulnerable=$((total_vulnerable + 1))
        fi
      # Otherwise treat as file or path
      else
        if [[ -f "$arg" ]]; then
          scan_directory "$(dirname "$arg")"
        else
          echo -e "${YELLOW}[!] Unknown argument: $arg${NC}"
        fi
      fi
    done
  else
    # No arguments - perform local system check
    echo -e "${CYAN}[*] No arguments provided. Running local system audit...${NC}"
    echo ""
    
    # Check local PHP installations
    if check_local_php; then
      total_vulnerable=$((total_vulnerable + 1))
    fi
    
    # Check PHP packages
    if check_packages; then
      total_vulnerable=$((total_vulnerable + 1))
    fi
  fi
  
  # Summary
  echo -e "${BLUE}================================================================================${NC}"
  echo -e "  PHP2Shell Audit Summary"
  echo -e "${BLUE}================================================================================${NC}"
  echo ""
  
  if [[ $total_vulnerable -gt 0 ]]; then
    echo -e "  ${RED}[!] $total_vulnerable VULNERABLE PHP installations detected!${NC}"
    echo ""
    echo -e "  ${YELLOW}RECOMMENDATION:${NC}"
    echo "    Immediate action required:"
    echo "    1. Update PHP to the latest patched version:"
    echo "       - PHP 8.3: Upgrade to 8.3.29 or higher"
    echo "       - PHP 8.2: Upgrade to 8.2.57 or higher"
    echo "       - PHP 8.1: Upgrade to 8.1.92 or higher"
    echo "       - PHP 8.0: Upgrade to 8.0.113 or higher"
    echo ""
    echo "    2. Apply patches from your distribution's package manager"
    echo "    3. Review PHP configuration for exposure to untrusted input"
    echo "    4. Check for signs of exploitation in web server logs"
    echo ""
    echo -e "  ${YELLOW}References:${NC}"
    echo "    https://nvd.nist.gov/vuln/detail/CVE-2026-109618"
    echo "    https://nvd.nist.gov/vuln/detail/CVE-2026-109619"
    echo "    https://security.paloaltonetworks.com/CVE-2026-109618"
    echo "    https://www.php.net/ChangeLog-8.php"
    echo ""
    exit 1
  else
    echo -e "  ${GREEN}[+] No vulnerable PHP installations detected.${NC}"
    echo ""
    echo -e "  ${GREEN}Good practice:${NC}"
    echo "    - Regularly update PHP to receive security patches"
    echo "    - Monitor PHP security advisories"
    echo "    - Consider upgrading to PHP 8.4+ for latest security features"
    echo ""
    exit 0
  fi
}

main "$@"
