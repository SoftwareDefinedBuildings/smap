local dns = require "dns"
local http = require "http"
local ipOps = require "ipOps"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local json = require "json"
local string = require "string"

description = [[
  Scans for Raritan
]]

author = "Gabe Fierro"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

portrule = shortport.http

action = function(host, port)
  local resp, redirect_url, title, s, response

  local s = nmap.new_socket()
  local status, error = s:connect(host, port, "ssl")
  if not status then
    return
  end
  local cert = s:get_ssl_certificate()
  local digest = cert:digest("md5")

  local isProliphix = string.match(cert.subject.commonName, 'proliphix')
  if not isProliphix then
    return
  end

  -- output a sMAP config file section
  local output_tab = stdnse.output_table()
  output_tab.type = 'smap.drivers.imt550c.IMT550C'
  output_tab.Metadata__Instrument__Manufacturer = cert.subject.organizationName
  output_tab.mac = host.mac_addr
  output_tab.ip = host.ip
  output_tab.readrate = 1

  return output_tab
end
