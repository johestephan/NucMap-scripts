#!/usr/bin/env bash
# ==============================================================================
# audit-php2shell.sh
# Audits local PHP installations, packages, running workers, and remote URLs
# for PHP2Shell vulnerabilities (CVE-2026-109618 and CVE-2026-109619).
#
# Affected Versions:
#   - PHP 8.5.0 - 8.5.11 (Fixed in 8.5.12)
#   - PHP 8.4.0 - 8.4.26 (Fixed in 8.4.27)
#   - PHP 8.3.0 - 8.3.35 (Fixed in 8.3.36)
#   - PHP 8.2.0 - 8.2.34 (Fixed in 8.2.35)
#   - PHP 5.4.x - 8.1.x  (Affected; EOL upstream unless distro-backported)
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

VULN_FINDINGS=0

# Returns 0 if vulnerable, 1 if patched/not vulnerable
is_vulnerable_version() {
  local version="$1"
  local major minor patch
  IFS='.' read -r major minor patch <<< "$version"
  patch="${patch%%[^0-9]*}"
  [[ -z "$major" || -z "$minor" || -z "$patch" ]] && return 1

  case "${major}.${minor}" in
    8.5) (( patch < 12 )) && return 0 || return 1 ;;
    8.4) (( patch < 27 )) && return 0 || return 1 ;;
    8.3) (( patch < 36 )) && return 0 || return 1 ;;
    8.2) (( patch < 35 )) && return 0 || return 1 ;;
    8.1|8.0|7.*|5.4|5.5|5.6) return 0 ;;
    *) return 1 ;;
  esac
}

parse_php_version() {
  local input="$1"
  echo "$input" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true
}

check_local_php() {
  echo -e "${CYAN}[*] Checking local PHP binaries & SAPI workers...${NC}"
  local found_any=0

  for bin in php php-fpm php-cgi FrankenPHP lsphp; do
    if command -v "$bin" &>/dev/null; then
      found_any=1
      local ver_out
      ver_out=$("$bin" -v 2>/dev/null | head -1 || true)
      local ver
      ver=$(parse_php_version "$ver_out")
      if [[ -n "$ver" ]]; then
        echo -e "  Binary ($bin): $ver_out"
        if is_vulnerable_version "$ver"; then
          echo -e "    ${RED}[!] VULNERABLE to PHP2Shell (CVE-2026-109618, CVE-2026-109619)${NC}"
          VULN_FINDINGS=$((VULN_FINDINGS + 1))
        else
          echo -e "    ${GREEN}[+] Patched ($ver)${NC}"
        fi
      fi
    fi
  done

  # Also check running PHP worker processes (from Unit 42 XQL anchor list)
  local running_workers
  running_workers=$(ps -eo comm,args 2>/dev/null | grep -E '^(php-fpm|php-cgi|lsphp|frankenphp|apache2|httpd)' || true)
  if [[ -n "$running_workers" ]]; then
    echo -e "  ${BLUE}[i] Active web/PHP worker processes detected:${NC}"
    echo "$running_workers" | head -5 | sed 's/^/      /'
  fi

  if [[ $found_any -eq 0 ]]; then
    echo -e "  ${GREEN}[+] No local PHP binaries found in PATH.${NC}"
  fi
  echo ""
}

check_packages() {
  echo -e "${CYAN}[*] Checking installed OS PHP packages...${NC}"
  local pkg_count=0

  if command -v dpkg-query &>/dev/null; then
    while IFS=$'\t' read -r status pkg raw_ver; do
      [[ "$status" != "install ok installed" ]] && continue
      pkg_count=$((pkg_count + 1))
      local ver
      ver=$(parse_php_version "$raw_ver")
      if [[ -n "$ver" ]]; then
        if is_vulnerable_version "$ver"; then
          echo -e "  $pkg ($raw_ver): ${YELLOW}[!] Base version $ver affected (verify distro security backport)${NC}"
          VULN_FINDINGS=$((VULN_FINDINGS + 1))
        else
          echo -e "  $pkg ($raw_ver): ${GREEN}[+] Patched ($ver)${NC}"
        fi
      fi
    done < <(dpkg-query -W -f='${Status}\t${Package}\t${Version}\n' '*php*' 2>/dev/null || true)
  elif command -v rpm &>/dev/null; then
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      pkg_count=$((pkg_count + 1))
      local ver
      ver=$(parse_php_version "$line")
      if [[ -n "$ver" ]] && is_vulnerable_version "$ver"; then
        echo -e "  $line: ${YELLOW}[!] Base version $ver affected (verify distro backport)${NC}"
        VULN_FINDINGS=$((VULN_FINDINGS + 1))
      else
        echo -e "  $line: ${GREEN}[+] OK${NC}"
      fi
    done < <(rpm -qa '*php*' 2>/dev/null || true)
  fi

  if [[ $pkg_count -eq 0 ]]; then
    echo -e "  ${GREEN}[+] No PHP packages installed.${NC}"
  fi
  echo ""
}

check_remote() {
  local url="$1"
  echo -e "${CYAN}[*] Checking remote target: $url${NC}"

  local headers
  headers=$(curl -ksI -A "NucMap-PHP2Shell-Auditor/1.0" -m 8 "$url" 2>/dev/null || true)
  if [[ -z "$headers" ]]; then
    echo -e "  ${YELLOW}[!] No HTTP response from $url${NC}\n"
    return
  fi

  local php_line
  php_line=$(echo "$headers" | grep -iE '^(X-Powered-By|Server):.*PHP/' | tr -d '\r' | head -1 || true)
  if [[ -n "$php_line" ]]; then
    local ver
    ver=$(parse_php_version "$php_line")
    echo -e "  Header: $php_line"
    if [[ -n "$ver" ]]; then
      if is_vulnerable_version "$ver"; then
        echo -e "  ${RED}[!] VULNERABLE: PHP $ver is affected by PHP2Shell (CVE-2026-109618, CVE-2026-109619)${NC}"
        VULN_FINDINGS=$((VULN_FINDINGS + 1))
      else
        echo -e "  ${GREEN}[+] PATCHED: PHP $ver is not vulnerable${NC}"
      fi
    fi
  else
    echo -e "  ${GREEN}[+] PHP version not disclosed in HTTP headers.${NC}"
  fi
  echo ""
}

main() {
  echo -e "${BLUE}================================================================================${NC}"
  echo -e "  PHP2Shell Vulnerability Auditor (CVE-2026-109618, CVE-2026-109619)"
  echo -e "${BLUE}================================================================================${NC}"
  echo ""

  if [[ $# -gt 0 ]]; then
    for arg in "$@"; do
      if [[ "$arg" =~ ^https?:// ]]; then
        check_remote "$arg"
      else
        check_remote "http://$arg"
      fi
    done
  else
    check_local_php
    check_packages
  fi

  if [[ $VULN_FINDINGS -gt 0 ]]; then
    echo -e "${RED}[!] Audit finished: $VULN_FINDINGS vulnerable or unverified PHP finding(s) detected.${NC}"
    echo -e "    Remediation: Upgrade to PHP >= 8.5.12, >= 8.4.27, >= 8.3.36, or >= 8.2.35."
    exit 1
  else
    echo -e "${GREEN}[+] Audit finished: No vulnerable PHP installations detected.${NC}"
    exit 0
  fi
}

main "$@"
