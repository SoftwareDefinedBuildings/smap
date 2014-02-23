local dns = require "dns"
local http = require "http"
local ipOps = require "ipOps"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local url = require "url"
local json = require "json"

description = [[
  Scans for CT80
]]

author = "Tyler Hoyt"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

portrule = shortport.http

action = function(host, port)
  local resp, redirect_url, title, jsonresp, _

  resp = http.get( host, port, '/tstat/model' )

  if ( not(resp.body) ) then
    return
  end

  rta = string.match(resp.body, 'CT80')
  if not rta then
    return
  end
  stdnse.print_debug(0, "Detected RTA CT80")

  _, jsonresp = json.parse(resp.body)

  -- output a sMAP config file section
  local output_tab = stdnse.output_table()
  output_tab.type = 'smap.drivers.thermostats.ct80.CT80'
  output_tab.Metadata__Instrument__Manufacturer = 'RTA'
  output_tab.Metadata__Instrument__Model = string.format(jsonresp['model'])
  output_tab.ip = host.ip
  output_tab.Rate = 1
  output_tab.user = ''

  return output_tab
end
