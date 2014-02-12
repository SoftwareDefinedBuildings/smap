local dns = require "dns"
local http = require "http"
local ipOps = require "ipOps"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local url = require "url"

description = [[
Shows the title of the default page of a web server.

The script will follow no more than one HTTP redirect, and only if the
redirection leads to the same host. The script may send a DNS query to
determine whether the host the redirect leads to has the same IP address as the
original target.
]]

---
--@output
-- Nmap scan report for scanme.nmap.org (74.207.244.221)
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_http-title: Go ahead and ScanMe!
--
-- @xmloutput
-- <elem key="title">Go ahead and ScanMe!</elem>
-- @xmloutput
-- <elem key="title">Wikipedia, the free encyclopedia</elem>
-- <elem key="redirect_url">http://en.wikipedia.org/wiki/Main_Page</elem>

author = "Diman Todorov"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}


portrule = shortport.http

action = function(host, port)
  local resp, redirect_url, title

  resp = http.get( host, port, '/' )

  -- check for a redirect
  if resp.location then
    redirect_url = resp.location[#resp.location]
    if resp.status and tostring( resp.status ):match( "30%d" ) then
      return {redirect_url = redirect_url}, ("Did not follow redirect to %s"):format( redirect_url )
    end
  end

  if ( not(resp.body) ) then
    return
  end

  if ( resp.header['server'] ~= 'Ubicom/1.1' ) then
    return
  end
  stdnse.print_debug(0, "Detected Ubicom server, proceeding to model detection")

  -- try and pull out the model tag
  -- this seems to be set as a javascript method call
  major, minor = string.match(resp.body, 'printStatusHead%([^\n]-,[^\n]-%"([a-zA-Z0-9]+)%"[^\n]-,[^\n]-%"([a-zA-Z0-9]+)%"[^\n]-%)')
  if (not major or not minor) then
    return
  end
  stdnse.print_debug(0, "Detected major version '%s', minor version '%s'", major, minor)

  -- output a sMAP config file section
  local output_tab = stdnse.output_table()
  output_tab.type = 'smap.drivers.nt160e.NT160e'
  output_tab.Metadata__Instrument__Manufacturer = 'Prolifix'
  output_tab.Metadata__Instrument__Model = string.format('%s%s', major, minor)
  output_tab.url = string.format('http://%s:%i/', host.ip, port.number)
  output_tab.login = ''
  output_tab.password = ''

  local output_str = string.format("%s%s", major, minor)
  return output_tab, output_str
end
