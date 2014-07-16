local dns = require "dns"
local http = require "http"
local ipOps = require "ipOps"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local json = require "json"
local string = require "string"

description = [[
  Scans for TCPLighting
]]

author = "Gabe Fierro"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

portrule = shortport.http

action = function(host, port)
  local resp, redirect_url, title

  resp = http.post(host.ip, port, '/gwr/gop.php', nil, nil, 'cmd=GWRLogin&data=%3Cgip%3E%3Cversion%3E1%3C%2Fversion%3E%3Cemail%3Eadmin%3C%2Femail%3E%3Cpassword%3Eadmin%3C%2Fpassword%3E%3C%2Fgip%3E&fmt=xml')

  if ( not(resp.body) ) then
    return
  end

  stdnse.print_debug(0, resp.body)

  isTCP = string.match(resp.body, '<gip>.*</gip>')
  if not isTCP then
    return
  end

  stdnse.print_debug(0, "Detected TCPLighting")

  -- output a sMAP config file section
  local output_tab = stdnse.output_table()
  output_tab.type = 'smap.drivers.tcplighting.TCP'
  output_tab.Metadata__Instrument__Manufacturer = 'GreenWave Reality Pte Ltd'
  output_tab.mac = host.mac_addr
  output_tab.ip = host.ip
  output_tab.readrate = 5

  return output_tab
end
