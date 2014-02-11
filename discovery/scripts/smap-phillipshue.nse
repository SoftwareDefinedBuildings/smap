local dns = require "dns"
local http = require "http"
local ipOps = require "ipOps"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local url = require "url"

description = [[
  Scans for Phillips Hue
]]

author = "Gabe Fierro"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

portrule = shortport.http

action = function(host, port)
  local resp, redirect_url, title

  resp = http.get( host, port, '/' )

  -- check for a redirect
--  if resp.location then
--    redirect_url = resp.location[#resp.location]
--    if resp.status and tostring( resp.status ):match( "30%d" ) then
--      return {redirect_url = redirect_url}, ("Did not follow redirect to %s"):format( redirect_url )
--    end
--  end

  if ( not(resp.body) ) then
    return
  end

  phillips = string.match(resp.body, 'hue personal wireless lighting')
  if not phillips then
    return
  end
  stdnse.print_debug(0, "Detected Phillips Hue")


  -- output a sMAP config file section
  local output_tab = stdnse.output_table()
  output_tab.type = 'smap.drivers.hue'
  output_tab.Metadata__Instrument__Manufacturer = 'Phillips'
  output_tab.Metadata__Instrument__Model = string.format('Hue')
  output_tab.ip = host.ip
  output_tab.Rate = 1

  output_tab.login = ''
  output_tab.password = ''

  -- local output_str = string.format("%s%s", major, minor)
  return output_tab
end
