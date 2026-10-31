local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local vulns = require "vulns"

description = [[
Template NSE script for NucMap service enumeration and vulnerability verification.
Provides structured output compatible with Nmap XML (-oX) and NucMap parsers.
]]

---
-- @usage
-- nmap -sV -p 80,443 --script nucmap-template <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | nucmap-template:
-- |   status: checked
-- |_  server: example

author = "johestephan"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html (MIT compatible)"
categories = {"discovery", "safe"}

portrule = shortport.http

action = function(host, port)
  local output = stdnse.output_table()
  local response = http.get(host, port, "/")

  if not response or not response.status then
    return nil
  end

  output.status = response.status
  if response.header and response.header["server"] then
    output.server = response.header["server"]
  end

  return output
end
