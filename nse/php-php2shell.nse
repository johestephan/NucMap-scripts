local nmap = require "nmap"
local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local vulns = require "vulns"

description = [[
Detects PHP services vulnerable to PHP2Shell (CVE-2026-109618 and CVE-2026-109619).

CVE-2026-109618: Remote Code Execution vulnerability where handling out-of-memory errors
via longjmp() leaves request memory uninitialized due to improper control flow management,
allowing attackers to reliably achieve RCE using out-of-memory (OOM) triggers.

CVE-2026-109619: Remote Code Execution vulnerability where longjmp() fatal error handling
leaves global memory pointing to freed memory regions. These regions can later be read or
branched on during subsequent requests, enabling attackers to execute arbitrary code.

Both vulnerabilities are rated 9.2 (CVSS 4.0) and are collectively known as PHP2Shell.
Over 22.6 million PHP instances are potentially vulnerable according to Palo Alto Networks
Cortex Xpanse telemetry (October 2026).

This script:
1. Identifies PHP version from HTTP headers and PHP info pages
2. Checks for vulnerable PHP versions (8.3.0-8.3.28, 8.2.0-8.2.56, 8.1.0-8.1.91, 8.0.0-8.0.112)
3. Attempts to trigger PHP2Shell-specific behavior patterns
4. Provides detection for default PHP configurations that may be vulnerable

References:
* https://nvd.nist.gov/vuln/detail/CVE-2026-109618
* https://nvd.nist.gov/vuln/detail/CVE-2026-109619
* https://security.paloaltonetworks.com/CVE-2026-109618
* https://security.paloaltonetworks.com/CVE-2026-109619
* https://unit42.paloaltonetworks.com/tag/CVE-2026-109618/
* https://unit42.paloaltonetworks.com/tag/CVE-2026-109619/
* https://unit42.paloaltonetworks.com/tag/PHP2Shell
* https://www.php.net/index.php
* https://www.php.net/ChangeLog-8.php
]]

---
-- @usage
-- nmap -sV --script php-php2shell -p 80,443,8080,8443 <target>
-- nmap -sV --script php-php2shell --script-args vulns.showall <target>
--
-- @args php-php2shell.aggressive Enable more aggressive detection (may cause false positives)
-- @args php-php2shell.timeout   Custom timeout for HTTP requests (default: 5s)
--
-- @output
-- PORT    STATE SERVICE
-- 80/tcp  open  http
-- | php-php2shell:
-- |   VULNERABLE:
-- |   PHP PHP2Shell Remote Code Execution (CVE-2026-109618, CVE-2026-109619)
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2026-109618 CVE:CVE-2026-109619
-- |     Risk factor: Critical
-- |       PHP version X.X.X is vulnerable to PHP2Shell RCE
-- |     Extra information:
-- |       PHP Version: 8.2.15
-- |       Detected via: X-Powered-By header
-- |       Server: Apache/2.4.57 (Unix) PHP/8.2.15
-- |     References:
-- |       https://nvd.nist.gov/vuln/detail/CVE-2026-109618
-- |       https://nvd.nist.gov/vuln/detail/CVE-2026-109619
-- |_      https://www.php.net/ChangeLog-8.php

author = "johestephan"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html (MIT compatible)"
categories = {"vuln", "safe", "discovery", "intrusive"}

-- Vulnerable PHP version ranges for PHP2Shell
-- Based on PHP Group security advisories and analysis
local VULNERABLE_VERSIONS = {
  -- PHP 8.3.x vulnerable versions
  { pattern = "^8\.3\.%d+", min = 0, max = 28, family = "8.3" },
  -- PHP 8.2.x vulnerable versions  
  { pattern = "^8\.2\.%d+", min = 0, max = 56, family = "8.2" },
  -- PHP 8.1.x vulnerable versions
  { pattern = "^8\.1\.%d+", min = 0, max = 91, family = "8.1" },
  -- PHP 8.0.x vulnerable versions
  { pattern = "^8\.0\.%d+", min = 0, max = 112, family = "8.0" },
}

-- Patched versions (non-vulnerable)
local PATCHED_VERSIONS = {
  ["8.3.29"] = true,
  ["8.3.30"] = true,
  ["8.2.57"] = true,
  ["8.2.58"] = true,
  ["8.1.92"] = true,
  ["8.1.93"] = true,
  ["8.0.113"] = true,
  ["8.0.114"] = true,
}

portrule = shortport.http

local function parse_version(version_str)
  if not version_str or type(version_str) ~= "string" then
    return nil, nil, nil
  end
  
  -- Normalize version string
  local normalized = version_str:match("(%d+\.%d+\.%d+)") or version_str:match("(%d+\.%d+)")
  if not normalized then
    return nil, nil, nil
  end
  
  -- Extract major, minor, patch
  local major, minor, patch = normalized:match("(%d+)%.(%d+)%.(%d+)")
  if major and minor and patch then
    return tonumber(major), tonumber(minor), tonumber(patch)
  end
  
  major, minor = normalized:match("(%d+)%.(%d+)")
  if major and minor then
    return tonumber(major), tonumber(minor), 0
  end
  
  return nil, nil, nil
end

local function is_vulnerable_version(version_str)
  local major, minor, patch = parse_version(version_str)
  if not major or not minor or patch == nil then
    return false, "Unknown version format"
  end
  
  -- Check if it's a patched version
  local full_version = string.format("%d.%d.%d", major, minor, patch)
  if PATCHED_VERSIONS[full_version] then
    return false, "Patched version"
  end
  
  -- Check if it's in a vulnerable range
  for _, range in ipairs(VULNERABLE_VERSIONS) do
    local range_major, range_minor = range.pattern:match("(%d+)%.(%d+)")
    range_major = tonumber(range_major)
    range_minor = tonumber(range_minor)
    
    if major == range_major and minor == range_minor then
      if patch >= range.min and patch <= range.max then
        return true, string.format("Vulnerable %s.x version", range.family)
      end
      -- If patch is higher than max, it's patched
      if patch > range.max then
        return false, "Version higher than vulnerable range"
      end
    end
  end
  
  -- PHP versions before 8.0 are not affected
  if major < 8 then
    return false, "PHP version < 8.0 not affected"
  end
  
  return false, "Not in vulnerable range"
end

local function extract_php_version_from_headers(response)
  if not response or not response.header then
    return nil
  end
  
  -- Check X-Powered-By header
  if response.header["x-powered-by"] then
    local version = response.header["x-powered-by"]:lower():match("php[^/]*(%d+\.%d+\.%d+)")
    if version then
      return version
    end
    version = response.header["x-powered-by"]:lower():match("php[^/]*(%d+\.%d+)")
    if version then
      return version
    end
  end
  
  -- Check Server header
  if response.header["server"] then
    local version = response.header["server"]:lower():match("php[^/]*(%d+\.%d+\.%d+)")
    if version then
      return version
    end
    version = response.header["server"]:lower():match("php[^/]*(%d+\.%d+)")
    if version then
      return version
    end
  end
  
  return nil
end

local function extract_php_version_from_body(response)
  if not response or not response.body then
    return nil
  end
  
  -- Look for PHP version in HTML comments or meta tags
  local version = response.body:match("PHP (%d+\.%d+\.%d+)")
  if version then
    return version
  end
  
  version = response.body:match("PHP/(%d+\.%d+\.%d+)")
  if version then
    return version
  end
  
  return nil
end

local function try_phpinfo_path(host, port)
  local paths = {
    "/phpinfo.php",
    "/info.php",
    "/php_info.php",
    "/test.php",
    "/pi.php",
  }
  
  for _, path in ipairs(paths) do
    local response = http.get(host, port, path)
    if response and response.status == 200 then
      local version = response.body:match("PHP Version[^>]*>(%d+\.%d+\.%d+)<")
      if version then
        return version
      end
      version = response.body:match("PHP Core[^>]*>(%d+\.%d+\.%d+)<")
      if version then
        return version
      end
    end
  end
  
  return nil
end

local function check_php2shell_patterns(host, port)
  -- These patterns are indicative of PHP2Shell exploitation attempts
  -- We check if the server responds in a way that suggests vulnerability
  local patterns = {
    -- OOM trigger via multipart upload with large file
    {
      path = "/upload.php",
      method = "POST",
      body = "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\nContent-Type: text/plain\r\n\r\nA" .. string.rep("A", 100000) .. "\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n",
      headers = { ["Content-Type"] = "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW" },
    },
    -- Upload.progress trigger (mentioned in Palo Alto advisories)
    {
      path = "/index.php",
      method = "POST",
      body = "UPLOAD_IDENTIFIER=test&PHP_SESSION_UPLOAD_PROGRESS=1",
      headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
    },
  }
  
  local aggressive = stdnse.get_script_args(SCRIPT_NAME .. ".aggressive")
  
  if not aggressive then
    return nil, "Aggressive detection not enabled"
  end
  
  for _, pattern in ipairs(patterns) do
    local response = http[pattern.method:lower()](host, port, pattern.path, { headers = pattern.headers }, pattern.body)
    if response and response.status then
      -- Check for error patterns that might indicate vulnerability
      if response.body and (
        response.body:lower():find("fatal error") or
        response.body:lower():find("allowed memory") or
        response.body:lower():find("out of memory") or
        response.body:lower():find("longjmp")
      ) then
        return true, "Potential PHP2Shell error pattern detected"
      end
      
      -- Check for unusual behavior (very short response, empty body, etc.)
      if response.status >= 500 then
        return true, "Server error potentially related to PHP2Shell"
      end
    end
  end
  
  return nil, "No PHP2Shell patterns detected"
end

action = function(host, port)
  local timeout = stdnse.get_script_args(SCRIPT_NAME .. ".timeout") or 5000
  local aggressive = stdnse.get_script_args(SCRIPT_NAME .. ".aggressive")
  
  host.targetname = host.targetname or "unknown"
  
  -- First, try to get PHP version from root page
  local response = http.get(host, port, "/", { timeout = timeout })
  
  local php_version = nil
  local detection_method = "unknown"
  
  if response and response.status then
    -- Try to extract from headers
    php_version = extract_php_version_from_headers(response)
    if php_version then
      detection_method = "HTTP headers"
    else
      -- Try to extract from body
      php_version = extract_php_version_from_body(response)
      if php_version then
        detection_method = "HTTP body"
      end
    end
  end
  
  -- Try phpinfo paths
  if not php_version then
    php_version = try_phpinfo_path(host, port)
    if php_version then
      detection_method = "phpinfo page"
    end
  end
  
  -- Try checking for PHP2Shell patterns (only if aggressive mode)
  local php2shell_detected, pattern_info = check_php2shell_patterns(host, port)
  
  local vuln_table = {
    title = "PHP PHP2Shell Remote Code Execution (CVE-2026-109618, CVE-2026-109619)",
    IDS = { 
      CVE = "CVE-2026-109618,CVE-2026-109619" 
    },
    risk_factor = "Critical",
    description = [[
PHP2Shell refers to two critical remote code execution vulnerabilities in PHP:

CVE-2026-109618: Out-of-memory error handling via longjmp() leaves request memory 
uninitialized, allowing attackers to reliably achieve RCE using OOM triggers.

CVE-2026-109619: Fatal error handling via longjmp() leaves global memory pointing 
to freed memory regions, enabling attackers to execute arbitrary code.

Both vulnerabilities affect PHP 8.0.x through 8.3.x prior to the patched versions.
These are being actively exploited in the wild as of October 2026.

Impact: Remote attackers can execute arbitrary code on vulnerable PHP servers without
authentication. Over 22.6 million PHP instances are potentially vulnerable according
to Palo Alto Networks telemetry.
    ]],
    references = {
      "https://nvd.nist.gov/vuln/detail/CVE-2026-109618",
      "https://nvd.nist.gov/vuln/detail/CVE-2026-109619",
      "https://security.paloaltonetworks.com/CVE-2026-109618",
      "https://security.paloaltonetworks.com/CVE-2026-109619",
      "https://unit42.paloaltonetworks.com/tag/PHP2Shell",
      "https://www.php.net/ChangeLog-8.php",
      "https://www.php.net/index.php"
    },
    dates = {
      disclosure = { year = "2026", month = "10", day = "20" },
      disclosure2 = { year = "2026", month = "10", day = "20" }
    },
    state = vulns.STATE.NOT_VULN,
    extra_info = {}
  }
  
  local server_header = "unknown"
  if response and response.header and response.header["server"] then
    server_header = response.header["server"]
  end
  
  if php_version then
    local is_vulnerable, reason = is_vulnerable_version(php_version)
    
    vuln_table.extra_info[#vuln_table.extra_info + 1] = "PHP Version: " .. php_version
    vuln_table.extra_info[#vuln_table.extra_info + 1] = "Detected via: " .. detection_method
    vuln_table.extra_info[#vuln_table.extra_info + 1] = "Server: " .. server_header
    
    if is_vulnerable then
      vuln_table.state = vulns.STATE.VULN
      vuln_table.extra_info[#vuln_table.extra_info + 1] = "Status: VULNERABLE to PHP2Shell (" .. reason .. ")"
      
      if php2shell_detected then
        vuln_table.extra_info[#vuln_table.extra_info + 1] = "Exploitation pattern: " .. pattern_info
      end
    else
      vuln_table.state = vulns.STATE.NOT_VULN
      vuln_table.extra_info[#vuln_table.extra_info + 1] = "Status: NOT VULNERABLE (" .. reason .. ")"
    end
  else
    -- Could not determine version, but check for patterns
    vuln_table.extra_info[#vuln_table.extra_info + 1] = "PHP Version: Not detected"
    vuln_table.extra_info[#vuln_table.extra_info + 1] = "Server: " .. server_header
    
    if php2shell_detected then
      vuln_table.state = vulns.STATE.LIKELY_VULN
      vuln_table.extra_info[#vuln_table.extra_info + 1] = "Status: LIKELY VULNERABLE (PHP2Shell pattern detected)"
      vuln_table.extra_info[#vuln_table.extra_info + 1] = "Exploitation pattern: " .. pattern_info
    else
      vuln_table.extra_info[#vuln_table.extra_info + 1] = "Status: Could not determine vulnerability (PHP version not found)"
    end
  end
  
  local show_all = stdnse.get_script_args(SCRIPT_NAME .. ".showall") or stdnse.get_script_args("vulns.showall")
  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  report:add_vulns(vuln_table)
  
  if show_all and vuln_table.state == vulns.STATE.NOT_VULN then
    return string.format(
      "NOT VULNERABLE (PHP Version: %s, Detected via: %s, Server: %s)",
      php_version or "unknown",
      detection_method,
      server_header
    )
  end
  
  return report:make_output()
end
