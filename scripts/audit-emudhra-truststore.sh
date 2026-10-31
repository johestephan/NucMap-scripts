#!/usr/bin/env bash
# ==============================================================================
# audit-emudhra-truststore.sh
# Audits local trust stores, PEM bundles, and certificate directories for the
# compromised eMudhra / emSign Intermediate & G3 Root CAs (CVE-2026-111943 /
# Mozilla Bug 2083449), as recommended by Unit 42 Interim Guidance.
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

# 16 Compromised Intermediate CA SHA-256 Fingerprints + 3 Distrusted G3 Roots
declare -A AFFECTED_HASHES=(
  ["42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493"]="COMPROMISED INTERMEDIATE: EM DV TLS CA - G3B (emSign Root)"
  ["45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE"]="COMPROMISED INTERMEDIATE: EM DV TLS CA - G3B (Sectigo Cross-Sign)"
  ["0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19"]="COMPROMISED INTERMEDIATE: EM DV TLS CA - G3C (emSign Root)"
  ["62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72"]="COMPROMISED INTERMEDIATE: EM DV TLS CA - G3C (Sectigo Cross-Sign)"
  ["98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B"]="COMPROMISED INTERMEDIATE: EM OV TLS CA - G3B (emSign Root)"
  ["5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699"]="COMPROMISED INTERMEDIATE: EM OV TLS CA - G3B (Sectigo Cross-Sign)"
  ["CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F"]="COMPROMISED INTERMEDIATE: EM OV TLS CA - G3C (emSign Root)"
  ["7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489"]="COMPROMISED INTERMEDIATE: EM OV TLS CA - G3C (Sectigo Cross-Sign)"
  ["E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838"]="COMPROMISED INTERMEDIATE: EM EV TLS CA - G3B (emSign Root)"
  ["579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512"]="COMPROMISED INTERMEDIATE: EM EV TLS CA - G3B (Sectigo Cross-Sign)"
  ["432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3"]="COMPROMISED INTERMEDIATE: EM EV TLS CA - G3C (emSign Root)"
  ["FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F"]="COMPROMISED INTERMEDIATE: EM EV TLS CA - G3C (Sectigo Cross-Sign)"
  ["9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4"]="COMPROMISED INTERMEDIATE: EM OV CS CA - G3B (emSign Root)"
  ["A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8"]="COMPROMISED INTERMEDIATE: EM OV CS CA - G3B (Sectigo Cross-Sign)"
  ["4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1"]="COMPROMISED INTERMEDIATE: EM OV CS CA - G3C (emSign Root)"
  ["84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD"]="COMPROMISED INTERMEDIATE: EM OV CS CA - G3C (Sectigo Cross-Sign)"
  ["86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B"]="DISTRUSTED ROOT: emSign ECC Root CA - G3"
  ["7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D"]="DISTRUSTED ROOT: emSign Root TLS CA - G3"
  ["F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5"]="DISTRUSTED ROOT: emSign Root CS CA - G3"
)

SEARCH_PATHS=("$@")
if [ ${#SEARCH_PATHS[@]} -eq 0 ]; then
  SEARCH_PATHS=(
    "/etc/ssl/certs"
    "/usr/share/ca-certificates"
    "/usr/local/share/ca-certificates"
  )
fi

echo -e "${CYAN}[*] Auditing trust stores for compromised eMudhra / emSign certificates (CVE-2026-111943)...${NC}"

FOUND_COUNT=0
SCANNED_FILES=0

scan_pem_file() {
  local file="$1"
  [ -f "$file" ] || return 0
  SCANNED_FILES=$((SCANNED_FILES + 1))

  # Extract SHA-256 fingerprint and Subject/Issuer of each certificate in the file/bundle
  while IFS='|' read -r fp subj issuer; do
    [ -z "$fp" ] && continue
    local clean_fp="${fp//:/}"
    clean_fp="${clean_fp^^}"

    if [[ -n "${AFFECTED_HASHES[$clean_fp]:-}" ]]; then
      echo -e "${RED}[!] MATCH: ${AFFECTED_HASHES[$clean_fp]}${NC}"
      echo -e "    File:        $file"
      echo -e "    Subject:     $subj"
      echo -e "    Issuer:      $issuer"
      echo -e "    SHA-256:     $clean_fp"
      FOUND_COUNT=$((FOUND_COUNT + 1))
    elif [[ "$subj" =~ (eMudhra|emSign|EM\ (DV|OV|EV)\ (TLS|CS)\ CA) ]] || [[ "$issuer" =~ (eMudhra|emSign|EM\ (DV|OV|EV)\ (TLS|CS)\ CA) ]]; then
      echo -e "${YELLOW}[!] eMudhra/emSign Certificate Present in Trust Store:${NC}"
      echo -e "    File:        $file"
      echo -e "    Subject:     $subj"
      echo -e "    Issuer:      $issuer"
      echo -e "    SHA-256:     $clean_fp"
      FOUND_COUNT=$((FOUND_COUNT + 1))
    fi
  done < <(
    awk '
      /-----BEGIN CERTIFICATE-----/ { cert=$0; in_cert=1; next }
      in_cert { cert=cert "\n" $0 }
      /-----END CERTIFICATE-----/ {
        in_cert=0
        print cert | "openssl x509 -noout -fingerprint -sha256 -subject -issuer 2>/dev/null | tr \"\n\" \"|\" | sed \"s/sha256 Fingerprint=//I; s/subject=//I; s/issuer=//I; s/|$//\""
        close("openssl x509 -noout -fingerprint -sha256 -subject -issuer 2>/dev/null | tr \"\n\" \"|\" | sed \"s/sha256 Fingerprint=//I; s/subject=//I; s/issuer=//I; s/|$//\"")
        print ""
      }
    ' "$file" 2>/dev/null
  )
}

for target_path in "${SEARCH_PATHS[@]}"; do
  if [ -f "$target_path" ]; then
    scan_pem_file "$target_path"
  elif [ -d "$target_path" ]; then
    while IFS= read -r -d '' cert_file; do
      scan_pem_file "$cert_file"
    done < <(find "$target_path" -type f \( -name "*.pem" -o -name "*.crt" -o -name "*.cer" \) ! -name "ca-certificates.crt" -print0 2>/dev/null)
  fi
done

echo ""
if [ "$FOUND_COUNT" -gt 0 ]; then
  echo -e "${RED}[!] Audit complete: $FOUND_COUNT eMudhra/emSign certificate(s) found across $SCANNED_FILES scanned files.${NC}"
  exit 1
else
  echo -e "${GREEN}[+] Audit complete: No compromised eMudhra/emSign certificates found ($SCANNED_FILES files scanned).${NC}"
  exit 0
fi
