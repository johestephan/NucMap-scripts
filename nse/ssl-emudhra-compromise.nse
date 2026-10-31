local nmap = require "nmap"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tls = require "tls"
local vulns = require "vulns"

description = [[
Detects TLS/SSL services using certificates issued by or chaining to compromised
eMudhra (emSign) Intermediate Certificate Authorities (CVE-2026-111943 /
Mozilla Bugzilla 2083449).

In October 2026, eight intermediate CA private keys belonging to Indian CA
eMudhra Limited (16 certificates total across native emSign Root G3 and Sectigo
AAA Certificate Services cross-signed hierarchies) were disclosed as compromised
due to a critical cryptographic entropy defect during key generation. Attackers
can trivially derive the private keys from the public intermediate certificates
to sign unauthorized TLS certificates and perform Meddler-in-the-Middle (MitM)
interception.

This script inspects both the leaf certificate (Subject, Issuer, AIA/CRL
extensions, SHA-256 fingerprint) and, when available, the full TLS certificate
chain presented during handshake against:
1. Exact SHA-256 fingerprints of all 16 compromised eMudhra intermediate CAs
2. Exact Common Names (CN) of the 8 compromised intermediate CAs
   (EM DV/OV/EV TLS CA - G3B/G3C, EM OV CS CA - G3B/G3C)
3. Distrusted eMudhra G3 Root CAs (emSign ECC Root CA - G3,
   emSign Root TLS CA - G3, emSign Root CS CA - G3)
4. Any other eMudhra / emSign certificate authority hierarchy indicators

References:
* https://bugzilla.mozilla.org/show_bug.cgi?id=2083449
* https://unit42.paloaltonetworks.com/emudhra-certificate-compromise/
]]

---
-- @usage
-- nmap -sV --script ssl-emudhra-compromise -p 443,8443 <target>
-- nmap -sV --script ssl-emudhra-compromise --script-args vulns.showall <target>
--
-- @args ssl-emudhra-compromise.showall Show certificate issuer details even when not vulnerable.
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | ssl-emudhra-compromise:
-- |   VULNERABLE:
-- |   eMudhra Compromised Intermediate CA Certificate (CVE-2026-111943)
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2026-111943
-- |     Risk factor: Critical
-- |       The service presents a TLS certificate issued by or chaining to a
-- |       compromised eMudhra (emSign) Intermediate CA whose private key can be
-- |       derived from its public certificate.
-- |     Extra information:
-- |       [CVE-2026-111943] Compromised eMudhra Intermediate CA detected
-- |       Leaf Subject: commonName=example.com
-- |       Leaf Issuer: commonName=EM DV TLS CA - G3B/organizationName=eMudhra Limited
-- |       Detection: Compromised Intermediate CA CN (EM DV TLS CA - G3B [TLS DV])
-- |     References:
-- |       https://bugzilla.mozilla.org/show_bug.cgi?id=2083449
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-111943
-- |_      https://unit42.paloaltonetworks.com/emudhra-certificate-compromise/

author = "johestephan"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html (MIT compatible)"
categories = {"vuln", "safe", "discovery"}
dependencies = {"https-redirect"}

-- 16 Compromised Intermediate CA SHA-256 Fingerprints (uppercase hex)
local COMPROMISED_INTERMEDIATE_SHA256 = {
  -- EM DV TLS CA - G3B
  ["42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493"] = "EM DV TLS CA - G3B (emSign Root TLS CA - G3)",
  ["45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE"] = "EM DV TLS CA - G3B (Sectigo AAA Cross-Signed)",
  -- EM DV TLS CA - G3C
  ["0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19"] = "EM DV TLS CA - G3C (emSign Root TLS CA - G3)",
  ["62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72"] = "EM DV TLS CA - G3C (Sectigo AAA Cross-Signed)",
  -- EM OV TLS CA - G3B
  ["98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B"] = "EM OV TLS CA - G3B (emSign Root TLS CA - G3)",
  ["5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699"] = "EM OV TLS CA - G3B (Sectigo AAA Cross-Signed)",
  -- EM OV TLS CA - G3C
  ["CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F"] = "EM OV TLS CA - G3C (emSign Root TLS CA - G3)",
  ["7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489"] = "EM OV TLS CA - G3C (Sectigo AAA Cross-Signed)",
  -- EM EV TLS CA - G3B
  ["E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838"] = "EM EV TLS CA - G3B (emSign Root TLS CA - G3)",
  ["579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512"] = "EM EV TLS CA - G3B (Sectigo AAA Cross-Signed)",
  -- EM EV TLS CA - G3C
  ["432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3"] = "EM EV TLS CA - G3C (emSign Root TLS CA - G3)",
  ["FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F"] = "EM EV TLS CA - G3C (Sectigo AAA Cross-Signed)",
  -- EM OV CS CA - G3B (Code Signing)
  ["9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4"] = "EM OV CS CA - G3B (emSign Root CS CA - G3)",
  ["A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8"] = "EM OV CS CA - G3B (Sectigo AAA Cross-Signed)",
  -- EM OV CS CA - G3C (Code Signing)
  ["4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1"] = "EM OV CS CA - G3C (emSign Root CS CA - G3)",
  ["84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD"] = "EM OV CS CA - G3C (Sectigo AAA Cross-Signed)",
}

-- 8 Compromised Intermediate CA Common Names (normalized lowercase)
local COMPROMISED_INTERMEDIATE_CNS = {
  ["em dv tls ca - g3b"] = "EM DV TLS CA - G3B [TLS DV]",
  ["em dv tls ca - g3c"] = "EM DV TLS CA - G3C [TLS DV]",
  ["em ov tls ca - g3b"] = "EM OV TLS CA - G3B [TLS OV]",
  ["em ov tls ca - g3c"] = "EM OV TLS CA - G3C [TLS OV]",
  ["em ev tls ca - g3b"] = "EM EV TLS CA - G3B [TLS EV]",
  ["em ev tls ca - g3c"] = "EM EV TLS CA - G3C [TLS EV]",
  ["em ov cs ca - g3b"]  = "EM OV CS CA - G3B [Code Signing]",
  ["em ov cs ca - g3c"]  = "EM OV CS CA - G3C [Code Signing]",
}

-- Distrusted eMudhra G3 Root CAs
local DISTRUSTED_ROOT_SHA256 = {
  ["86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B"] = "emSign ECC Root CA - G3",
  ["7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D"] = "emSign Root TLS CA - G3",
  ["F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5"] = "emSign Root CS CA - G3",
}

local DISTRUSTED_ROOT_CNS = {
  ["emsign ecc root ca - g3"] = "emSign ECC Root CA - G3",
  ["emsign root tls ca - g3"] = "emSign Root TLS CA - G3",
  ["emsign root cs ca - g3"]  = "emSign Root CS CA - G3",
}

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

local function normalize_cn(str)
  if not str or type(str) ~= "string" then
    return ""
  end
  -- Normalize spaces and en-dashes/hyphens
  return str:lower():gsub("\226\128\147", "-"):gsub("%s+", " "):gsub("^%s*(.-)%s*$", "%1")
end

local function format_dn(name_table)
  if not name_table or type(name_table) ~= "table" then
    return "unknown"
  end
  local parts = {}
  local order = { "commonName", "organizationName", "organizationalUnitName", "countryName" }
  for _, k in ipairs(order) do
    if name_table[k] then
      parts[#parts + 1] = string.format("%s=%s", k, tostring(name_table[k]))
    end
  end
  if #parts == 0 then
    for k, v in pairs(name_table) do
      if type(k) == "string" then
        parts[#parts + 1] = string.format("%s=%s", k, tostring(v))
      end
    end
  end
  return table.concat(parts, "/")
end

local function get_cert_sha256(cert)
  if not cert or type(cert.digest) ~= "function" then
    return nil
  end
  local ok, raw = pcall(cert.digest, cert, "sha256")
  if not ok or not raw then
    return nil
  end
  return stdnse.tohex(raw):upper()
end

-- Attempt a TLS 1.2 handshake to retrieve the full certificate chain if possible
local function fetch_tls_chain(host, port)
  local sock = nmap.new_socket()
  sock:set_timeout(5000)
  local status = sock:connect(host, port)
  if not status then
    return nil
  end

  local sni = tls.servername(host)
  local hello_opts = { protocol = "TLSv1.2" }
  if sni and tls.extension_helpers and tls.extension_helpers["server_name"] then
    hello_opts.extensions = {
      ["server_name"] = tls.extension_helpers["server_name"](sni)
    }
  end

  local hello = tls.client_hello(hello_opts)
  status = sock:send(hello)
  if not status then
    sock:close()
    return nil
  end

  local buffer = ""
  local i = 1
  local fragment
  local chain_certs = {}
  local done = false

  while not done do
    local record, more
    i, record, more = tls.record_read(buffer, i, fragment)
    if record == nil then
      if not more then
        break
      end
      local ok
      ok, buffer = tls.record_buffer(sock, buffer, i)
      if not ok then
        break
      end
      i, record = tls.record_read(buffer, i, fragment)
      if record == nil then
        break
      end
    end
    fragment = record.fragment

    if record and record.body then
      for j = 1, #record.body do
        local b = record.body[j]
        if record.type == "alert" and b.level == "fatal" then
          done = true
        elseif record.type == "handshake" then
          if b.type == "certificate" and b.certificates then
            for _, der in ipairs(b.certificates) do
              local parsed = sslcert.parse_ssl_certificate(der)
              if parsed then
                chain_certs[#chain_certs + 1] = parsed
              end
            end
          elseif b.type == "server_hello_done" then
            done = true
          end
        end
      end
    end
  end

  sock:close()
  if #chain_certs > 0 then
    return chain_certs
  end
  return nil
end

local function inspect_certificate(cert, position_label)
  local findings = {
    compromised = false,
    distrusted_emudhra = false,
    reasons = {}
  }

  local sha256 = get_cert_sha256(cert)
  local subj_cn = cert.subject and cert.subject.commonName or ""
  local iss_cn  = cert.issuer and cert.issuer.commonName or ""
  local subj_org = cert.subject and cert.subject.organizationName or ""
  local iss_org  = cert.issuer and cert.issuer.organizationName or ""

  local norm_subj_cn = normalize_cn(subj_cn)
  local norm_iss_cn  = normalize_cn(iss_cn)
  local norm_subj_org = normalize_cn(subj_org)
  local norm_iss_org  = normalize_cn(iss_org)

  -- 1. Check exact SHA-256 against the 16 compromised intermediate certificates
  if sha256 and COMPROMISED_INTERMEDIATE_SHA256[sha256] then
    findings.compromised = true
    findings.reasons[#findings.reasons + 1] = string.format(
      "%s SHA-256 matches compromised intermediate %s (%s)",
      position_label, COMPROMISED_INTERMEDIATE_SHA256[sha256], sha256
    )
  end

  -- 2. Check Subject CN and Issuer CN against the 8 compromised intermediate CAs
  if COMPROMISED_INTERMEDIATE_CNS[norm_subj_cn] then
    findings.compromised = true
    findings.reasons[#findings.reasons + 1] = string.format(
      "%s Subject CN is compromised intermediate %s",
      position_label, COMPROMISED_INTERMEDIATE_CNS[norm_subj_cn]
    )
  end
  if COMPROMISED_INTERMEDIATE_CNS[norm_iss_cn] then
    findings.compromised = true
    findings.reasons[#findings.reasons + 1] = string.format(
      "%s Issuer CN is compromised intermediate %s",
      position_label, COMPROMISED_INTERMEDIATE_CNS[norm_iss_cn]
    )
  end

  -- 3. Check Distrusted eMudhra G3 Root CAs
  if sha256 and DISTRUSTED_ROOT_SHA256[sha256] then
    findings.distrusted_emudhra = true
    findings.reasons[#findings.reasons + 1] = string.format(
      "%s SHA-256 matches distrusted eMudhra G3 Root %s (%s)",
      position_label, DISTRUSTED_ROOT_SHA256[sha256], sha256
    )
  end
  if DISTRUSTED_ROOT_CNS[norm_subj_cn] then
    findings.distrusted_emudhra = true
    findings.reasons[#findings.reasons + 1] = string.format(
      "%s Subject CN matches distrusted eMudhra G3 Root (%s)",
      position_label, DISTRUSTED_ROOT_CNS[norm_subj_cn]
    )
  end
  if DISTRUSTED_ROOT_CNS[norm_iss_cn] then
    findings.distrusted_emudhra = true
    findings.reasons[#findings.reasons + 1] = string.format(
      "%s Issuer CN matches distrusted eMudhra G3 Root (%s)",
      position_label, DISTRUSTED_ROOT_CNS[norm_iss_cn]
    )
  end

  -- 4. Check broader eMudhra / emSign CA hierarchy indicators
  if norm_iss_org:find("emudhra", 1, true) or norm_iss_org:find("emsign", 1, true)
     or norm_iss_cn:find("emudhra", 1, true) or norm_iss_cn:find("emsign", 1, true) then
    findings.distrusted_emudhra = true
    findings.reasons[#findings.reasons + 1] = string.format(
      "%s issued by eMudhra/emSign CA (%s)",
      position_label, format_dn(cert.issuer)
    )
  end

  if norm_subj_org:find("emudhra", 1, true) or norm_subj_org:find("emsign", 1, true)
     or norm_subj_cn:find("emsign", 1, true) then
    findings.distrusted_emudhra = true
    findings.reasons[#findings.reasons + 1] = string.format(
      "%s Subject belongs to eMudhra/emSign hierarchy (%s)",
      position_label, format_dn(cert.subject)
    )
  end

  -- 5. Check X509v3 extensions (AIA / CRL URLs pointing to emsign.com or emudhra.com)
  if cert.extensions then
    for _, ext in ipairs(cert.extensions) do
      local val = (ext.value or ""):lower()
      if val:find("emsign.com", 1, true) or val:find("emudhra.com", 1, true) then
        findings.distrusted_emudhra = true
        findings.reasons[#findings.reasons + 1] = string.format(
          "%s extension '%s' references eMudhra/emSign PKI endpoint",
          position_label, ext.name or "X509v3"
        )
      end
    end
  end

  return findings
end

action = function(host, port)
  host.targetname = tls.servername(host)
  local status, leaf_cert = sslcert.getCertificate(host, port)
  if not status or not leaf_cert then
    stdnse.debug1("Failed to retrieve SSL certificate: %s", leaf_cert or "unknown")
    return nil
  end

  -- Fetch full TLS certificate chain if possible, fallback to leaf certificate
  local chain = fetch_tls_chain(host, port)
  if not chain or #chain == 0 then
    chain = { leaf_cert }
  end

  local is_compromised = false
  local is_distrusted_emudhra = false
  local all_reasons = {}
  local seen_reasons = {}

  for idx, c in ipairs(chain) do
    local label = (idx == 1) and "Leaf Certificate" or string.format("Chain Certificate #%d", idx)
    local res = inspect_certificate(c, label)
    if res.compromised then
      is_compromised = true
    end
    if res.distrusted_emudhra then
      is_distrusted_emudhra = true
    end
    for _, r in ipairs(res.reasons) do
      if not seen_reasons[r] then
        seen_reasons[r] = true
        all_reasons[#all_reasons + 1] = r
      end
    end
  end

  local vuln_table = {
    title = "eMudhra Compromised Intermediate CA Certificate (CVE-2026-111943)",
    IDS = { CVE = "CVE-2026-111943" },
    risk_factor = "Critical",
    description = [[
Eight intermediate CA private keys belonging to Indian CA eMudhra Limited
(16 certificates across emSign Root G3 and Sectigo cross-signed paths) were
compromised due to insufficient randomness during key generation. Attackers can
derive the private keys from the public intermediate certificates to forge
unauthorized TLS certificates and perform MitM traffic interception.]],
    references = {
      "https://bugzilla.mozilla.org/show_bug.cgi?id=2083449",
      "https://unit42.paloaltonetworks.com/emudhra-certificate-compromise/",
      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-111943"
    },
    dates = {
      disclosure = { year = "2026", month = "10", day = "17" }
    },
    state = vulns.STATE.NOT_VULN,
    extra_info = {}
  }

  local leaf_sha256 = get_cert_sha256(leaf_cert) or "unknown"
  local leaf_subj = format_dn(leaf_cert.subject)
  local leaf_iss  = format_dn(leaf_cert.issuer)

  if is_compromised then
    vuln_table.state = vulns.STATE.VULN
    vuln_table.extra_info[#vuln_table.extra_info + 1] =
      "[CVE-2026-111943] Compromised eMudhra Intermediate CA detected on TLS service"
    vuln_table.extra_info[#vuln_table.extra_info + 1] = "Leaf Subject: " .. leaf_subj
    vuln_table.extra_info[#vuln_table.extra_info + 1] = "Leaf Issuer:  " .. leaf_iss
    vuln_table.extra_info[#vuln_table.extra_info + 1] = "Leaf SHA-256: " .. leaf_sha256
    for _, reason in ipairs(all_reasons) do
      vuln_table.extra_info[#vuln_table.extra_info + 1] = "Detection:    " .. reason
    end
  elseif is_distrusted_emudhra then
    vuln_table.state = vulns.STATE.LIKELY_VULN
    vuln_table.risk_factor = "High"
    vuln_table.extra_info[#vuln_table.extra_info + 1] =
      "[CVE-2026-111943] Distrusted eMudhra / emSign CA hierarchy detected on TLS service"
    vuln_table.extra_info[#vuln_table.extra_info + 1] = "Leaf Subject: " .. leaf_subj
    vuln_table.extra_info[#vuln_table.extra_info + 1] = "Leaf Issuer:  " .. leaf_iss
    vuln_table.extra_info[#vuln_table.extra_info + 1] = "Leaf SHA-256: " .. leaf_sha256
    for _, reason in ipairs(all_reasons) do
      vuln_table.extra_info[#vuln_table.extra_info + 1] = "Detection:    " .. reason
    end
  else
    vuln_table.extra_info[#vuln_table.extra_info + 1] = "Leaf Subject: " .. leaf_subj
    vuln_table.extra_info[#vuln_table.extra_info + 1] = "Leaf Issuer:  " .. leaf_iss
    vuln_table.extra_info[#vuln_table.extra_info + 1] = "Leaf SHA-256: " .. leaf_sha256
  end

  local show_all = stdnse.get_script_args(SCRIPT_NAME .. ".showall")
  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  report:add_vulns(vuln_table)

  if show_all and vuln_table.state == vulns.STATE.NOT_VULN then
    return string.format(
      "NOT VULNERABLE (Issuer: %s | Subject: %s | SHA-256: %s)",
      leaf_iss, leaf_subj, leaf_sha256
    )
  end

  return report:make_output()
end
