local dns = require "dns"
local http = require "http"
local ipOps = require "ipOps"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local json = require "json"
local string = require "string"

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

  local body = resp.body

  if ( not(body) ) then
    return
  end

  -- check if Phillips

  local philips = string.match(body, 'hue personal wireless lighting')
  if ( (not philips) ) then
    return
  end

  -- register nmap user. Press bridge button, but you don't need to
  local new_user_req = {username = 'smapuser123', devicetype = 'smapuser123'}
  local json_req = json.generate(new_user_req)
  stdnse.print_debug(0, json_req)
  local httpdata = http.post(host.ip, port, '/api', nil, nil, json_req)
  if not httpdata.status == 200 then
    return
  end

  local hue_config = http.get(host.ip, port, '/api/smapuser123/config', nil)
  stdnse.print_debug(0, hue_config.body)
  local status, hue = json.parse(hue_config.body)

  if not status then
    return
  end

  -- output a sMAP config file section
  local output_tab = stdnse.output_table()
  output_tab.type = 'smap.drivers.hue.HUE'
  output_tab.Metadata__Instrument__Manufacturer = 'Phillips'
  output_tab.Metadata__Instrument__Model = hue['name']
  output_tab.Metadata__SoftwareVersion = hue['swversion']
  output_tab.mac = host.mac_addr
  output_tab.ip = host.ip
  output_tab.Rate = 1
  output_tab.user = 'smapuser123'

  return output_tab
end
