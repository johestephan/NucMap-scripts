local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local vulns = require "vulns"

description = [[
Detects PHP services vulnerable to PHP2Shell (CVE-2026-109618 and CVE-2026-109619).

* CVE-2026-109618: Remote Code Execution vulnerability where handling out-of-memory
  (OOM) errors via longjmp() leaves request memory uninitialized due to improper
  control flow management, allowing attackers to reliably achieve RCE using OOM triggers.
* CVE-2026-109619: Remote Code Execution / Use-After-Free vulnerability where
  longjmp() fatal error handling (notably in session upload progress and multipart
  handling) leaves global memory pointing to freed memory regions across requests on
  the same worker process.

Both vulnerabilities are rated CVSS 4.0 9.2 (Critical) and affect PHP 5.4 through 8.5
prior to the October 21, 2026 security releases:
* PHP 8.5.0 - 8.5.11 (Fixed in 8.5.12)
* PHP 8.4.0 - 8.4.26 (Fixed in 8.4.27)
* PHP 8.3.0 - 8.3.35 (Fixed in 8.3.36)
* PHP 8.2.0 - 8.2.34 (Fixed in 8.2.35)
* PHP 5.4.x - 8.1.x (End-of-Life upstream; vulnerable unless vendor-backported)

References:
* https://nvd.nist.gov/vuln/detail/CVE-2026-109618
* https://nvd.nist.gov/vuln/detail/CVE-2026-109619
* https://security.paloaltonetworks.com/CVE-2026-109618
* https://unit42.paloaltonetworks.com/threat-brief-php-cve-2026-109618-cve-2026-109619/
]]

---
-- @usage
-- nmap -sV --script php-php2shell -p 80,443,8080,8443 <target>
-- nmap -sV --script php-php2shell --script-args php-php2shell.showall=1 <target>
--
-- @args php-php2shell.showall    Show PHP version details even when patched/not vulnerable.
-- @args php-php2shell.aggressive Enable active probing for upload.progress / OOM error patterns.
-- @args php-php2shell.timeout    Custom HTTP request timeout in ms (default: 5000).
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | php-php2shell:
-- |   VULNERABLE:
-- |   PHP PHP2Shell Remote Code Execution (CVE-2026-109618, CVE-2026-109619)
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2026-109618  CVE:CVE-2026-109619
-- |     Risk factor: Critical  CVSSv4: 9.2
-- |       The remote PHP runtime is vulnerable to PHP2Shell RCE (longjmp OOM & UAF).
-- |     Extra information:
-- |       [CVE-2026-109618] PHP 8.3.12 vulnerable to PHP2Shell OOM longjmp RCE
-- |       [CVE-2026-109619] PHP 8.3.12 vulnerable to PHP2Shell fatal error UAF RCE
-- |       PHP Version:  8.3.12 (Fixed in 8.3.36)
-- |       Detected via: X-Powered-By header
-- |       Server:       Apache/2.4.58 (Debian)
-- |     References:
-- |       https://nvd.nist.gov/vuln/detail/CVE-2026-109618
-- |       https://nvd.nist.gov/vuln/detail/CVE-2026-109619
-- |_      https://security.paloaltonetworks.com/CVE-2026-109618

author = "johestephan"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html (MIT compatible)"
categories = {"vuln", "safe", "discovery"}

portrule = shortport.http

-- Minimum patched patch-level per supported PHP 8.x branch
local FIXED_BRANCH_MIN_PATCH = {
  ["8.5"] = 12, -- Fixed in 8.5.12
  ["8.4"] = 27, -- Fixed in 8.4.27
  ["8.3"] = 36, -- Fixed in 8.3.36
  ["8.2"] = 35, -- Fixed in 8.2.35
}

local function parse_version(version_str)
  if not version_str or type(version_str) ~= "string" then
    return nil, nil, nil
  end

  local major, minor, patch = version_str:match("(%d+)%.(%d+)%.(%d+)")
  if major and minor and patch then
    return tonumber(major), tonumber(minor), tonumber(patch)
  end

  major, minor = version_str:match("(%d+)%.(%d+)")
  if major and minor then
    return tonumber(major), tonumber(minor), 0
  end

  return nil, nil, nil
end

local function evaluate_php_version(version_str)
  local major, minor, patch = parse_version(version_str)
  if not major or not minor or patch == nil then
    return false, nil, "Unrecognized PHP version format"
  end

  local branch = string.format("%d.%d", major, minor)

  -- PHP 8.2 through 8.5 have official upstream patches
  local min_fixed = FIXED_BRANCH_MIN_PATCH[branch]
  if min_fixed then
    if patch < min_fixed then
      return true, "VULN", string.format("PHP %s.%d < %s.%d (patched in %s.%d)", branch, patch, branch, min_fixed, branch, min_fixed)
    else
      return false, "NOT_VULN", string.format("PHP %s.%d >= %s.%d (patched)", branch, patch, branch, min_fixed)
    end
  end

  -- PHP 8.0 and 8.1, PHP 7.x, and PHP 5.4 - 5.6 are affected and EOL upstream
  if (major == 8 and (minor == 0 or minor == 1))
     or (major == 7)
     or (major == 5 and minor >= 4) then
    return true, "VULN", string.format("PHP %d.%d.%d is in affected range (5.4 - 8.5) and EOL upstream (verify distro backports)", major, minor, patch)
  end

  if major > 8 or (major == 8 and minor > 5) then
    return false, "NOT_VULN", "Newer than affected branches"
  end

  return false, "NOT_VULN", "Outside affected PHP 5.4 - 8.5 branches"
end

local function extract_php_from_text(str)
  if not str or type(str) ~= "string" then
    return nil
  end
  return str:match("[Pp][Hh][Pp][/%s%-]+v?(%d+%.%d+%.%d+)")
      or str:match("[Pp][Hh][Pp][/%s%-]+v?(%d+%.%d+)")
end

local function extract_php_version_from_service(port)
  if not port or not port.version then
    return nil, nil
  end
  local fields = {
    { val = port.version.version,   label = "Nmap service version" },
    { val = port.version.product,   label = "Nmap service product" },
    { val = port.version.extrainfo, label = "Nmap service extrainfo" },
  }
  for _, f in ipairs(fields) do
    if f.val then
      local v = extract_php_from_text(f.val)
      if not v and port.version.product and port.version.product:lower():find("php", 1, true) then
        v = tostring(f.val):match("(%d+%.%d+%.%d+)")
      end
      if v then
        return v, f.label
      end
    end
  end
  return nil, nil
end

local function extract_php_version_from_headers(response)
  if not response or not response.header then
    return nil, nil
  end

  local header_keys = { "x-powered-by", "server", "x-generator" }
  for _, key in ipairs(header_keys) do
    local val = response.header[key]
    if val then
      local v = extract_php_from_text(val)
      if v then
        return v, string.format("HTTP '%s' header (%s)", key, val)
      end
    end
  end
  return nil, nil
end

local function extract_php_version_from_body(response)
  if not response or not response.body then
    return nil
  end
  return response.body:match("PHP Version[^%d]*(%d+%.%d+%.%d+)")
      or response.body:match("PHP/(%d+%.%d+%.%d+)")
end

local function probe_phpinfo_paths(host, port, timeout)
  local paths = {
    "/phpinfo.php",
    "/info.php",
    "/php_info.php",
    "/test.php",
  }

  for _, path in ipairs(paths) do
    local resp = http.get(host, port, path, { timeout = timeout })
    if resp and resp.status == 200 and resp.body then
      local v = resp.body:match("PHP Version</td><td[^>]*>(%d+%.%d+%.%d+)")
             or resp.body:match("<h1[^>]*>PHP Version (%d+%.%d+%.%d+)</h1>")
      if v then
        return v, "Exposed phpinfo page (" .. path .. ")"
      end
    end
  end
  return nil, nil
end

local function probe_aggressive_patterns(host, port, timeout)
  local resp = http.post(
    host,
    port,
    "/index.php",
    {
      timeout = timeout,
      header = { ["Content-Type"] = "application/x-www-form-urlencoded" }
    },
    nil,
    "UPLOAD_IDENTIFIER=nucmap_probe&PHP_SESSION_UPLOAD_PROGRESS=1"
  )

  if resp and resp.body then
    local body_low = resp.body:lower()
    if body_low:find("fatal error", 1, true)
       or body_low:find("allowed memory size of", 1, true)
       or body_low:find("out of memory", 1, true) then
      return true, "PHP fatal/memory error exposed on session.upload_progress probe"
    end
  end
  return false, nil
end

action = function(host, port)
  local timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 5000
  local aggressive = stdnse.get_script_args(SCRIPT_NAME .. ".aggressive")

  local php_version, detection_method = extract_php_version_from_service(port)
  local response = http.get(host, port, "/", { timeout = timeout })

  if not php_version and response then
    php_version, detection_method = extract_php_version_from_headers(response)
    if not php_version then
      local body_ver = extract_php_version_from_body(response)
      if body_ver then
        php_version = body_ver
        detection_method = "HTTP response body"
      end
    end
  end

  if not php_version then
    php_version, detection_method = probe_phpinfo_paths(host, port, timeout)
  end

  local pattern_hit, pattern_info = false, nil
  if aggressive then
    pattern_hit, pattern_info = probe_aggressive_patterns(host, port, timeout)
  end

  local server_header = (response and response.header and response.header["server"]) or "unknown"

  local vuln_table = {
    title = "PHP PHP2Shell Remote Code Execution (CVE-2026-109618, CVE-2026-109619)",
    IDS = {
      CVE = { "CVE-2026-109618", "CVE-2026-109619" }
    },
    risk_factor = "Critical",
    scores = {
      CVSSv4 = "9.2"
    },
    description = [[
PHP2Shell comprises two critical Remote Code Execution (RCE) vulnerabilities in PHP
(versions 5.4 through 8.5 prior to 8.2.35, 8.3.36, 8.4.27, and 8.5.12):
* CVE-2026-109618: Out-of-memory error handling via longjmp() leaves request memory
  uninitialized due to improper control flow management, enabling reliable RCE.
* CVE-2026-109619: Fatal error handling via longjmp() leaves global memory pointing
  to freed memory regions (Use-After-Free) across subsequent requests on a worker.]],
    references = {
      "https://nvd.nist.gov/vuln/detail/CVE-2026-109618",
      "https://nvd.nist.gov/vuln/detail/CVE-2026-109619",
      "https://security.paloaltonetworks.com/CVE-2026-109618",
      "https://security.paloaltonetworks.com/CVE-2026-109619",
      "https://unit42.paloaltonetworks.com/threat-brief-php-cve-2026-109618-cve-2026-109619/"
    },
    dates = {
      disclosure = { year = "2026", month = "10", day = "20" }
    },
    state = vulns.STATE.NOT_VULN,
    extra_info = {}
  }

  if php_version then
    local is_vuln, _, reason = evaluate_php_version(php_version)
    if is_vuln then
      vuln_table.state = vulns.STATE.VULN
      vuln_table.extra_info[#vuln_table.extra_info + 1] =
        string.format("[CVE-2026-109618] PHP %s vulnerable to PHP2Shell OOM longjmp RCE", php_version)
      vuln_table.extra_info[#vuln_table.extra_info + 1] =
        string.format("[CVE-2026-109619] PHP %s vulnerable to PHP2Shell fatal error UAF RCE", php_version)
    end
    vuln_table.extra_info[#vuln_table.extra_info + 1] = "PHP Version:  " .. php_version
    vuln_table.extra_info[#vuln_table.extra_info + 1] = "Assessment:   " .. reason
    vuln_table.extra_info[#vuln_table.extra_info + 1] = "Detected via: " .. (detection_method or "unknown")
    vuln_table.extra_info[#vuln_table.extra_info + 1] = "Server:       " .. server_header
    if pattern_hit and pattern_info then
      vuln_table.extra_info[#vuln_table.extra_info + 1] = "Active Probe: " .. pattern_info
    end
  elseif pattern_hit then
    vuln_table.state = vulns.STATE.LIKELY_VULN
    vuln_table.extra_info[#vuln_table.extra_info + 1] =
      "[CVE-2026-109618] Potential PHP2Shell error behavior detected"
    vuln_table.extra_info[#vuln_table.extra_info + 1] = "Active Probe: " .. pattern_info
    vuln_table.extra_info[#vuln_table.extra_info + 1] = "Server:       " .. server_header
  end

  local show_all = stdnse.get_script_args(SCRIPT_NAME .. ".showall") or stdnse.get_script_args("vulns.showall")
  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  report:add_vulns(vuln_table)

  if show_all and vuln_table.state == vulns.STATE.NOT_VULN then
    return string.format(
      "NOT VULNERABLE (PHP Version: %s | Source: %s | Server: %s)",
      php_version or "not disclosed",
      detection_method or "none",
      server_header
    )
  end

  return report:make_output()
end
