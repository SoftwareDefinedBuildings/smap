"""
Copyright (c) 2011, 2012, Regents of the University of California
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions 
are met:

 - Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
 - Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the
   distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL 
THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED 
OF THE POSSIBILITY OF SUCH DAMAGE.
"""
##
## PG&E Green button data downloader
##
## @author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
## 
## Based on https://gist.github.com/3131346 and Andrew Krioukov's
## sMAPv1 PG&E driver for the old format of data.
## 

# [/1625chestnut]
# type = smap.drivers.xml.XMLDriver
# Uri = python://smap.drivers.pge.update
# Xslt = ../../xslt/greenbutton.xsl
# Period = 86400
# Username = <username>
# Password = <password>
## optional
# Type = electric
# From = 1/1/2012
# To = 2/1/2012

import os
import errno
import re
import mechanize
import datetime
import zipfile
from lxml import etree
from cStringIO import StringIO

from smap.drivers import xml

agent = "User-Agent: Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; " \
    "rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3"

def select_form(forms, name):
  form = None
  for f in forms:
    if f.name == name:
      if form != None:
        raise ValueError("Error: multiple forms found with name = " + name)
      form = f

  if form == None:
    raise ValueError("Error: no forms found with name = " + name)

  return form

def update(opts):
    br = mechanize.Browser()
    # not sure if these are all still necessary
    br.set_debug_http(False)
    br.set_handle_equiv(False) # Otherwise, the loading page goes into an inf loop
    br.set_handle_robots(False)
    br.set_handle_referer(False)
    br.set_handle_refresh(False)

    def request(req):
        req.add_header("User-Agent", agent) 
        return br.open(req)

    print "Get login page"
    req = mechanize.Request("https://www.pge.com/myenergyweb/appmanager/pge/customer")
    req.add_header("User-Agent", agent)
    br.open(req)

    print "Logging in"
    f = select_form(br.forms(), 'login')
    f['USER'] = opts.get('Username')
    f['PASSWORD'] = opts.get('Password')
    request(f.click())

    print "Continue to opower"
    request(br.click_link(text="My Usage"))

    print "Continue pg&e-side sso"
    f = br.forms().next()           # get the first form
    request(f.click())

    print "Continue the opower sso"
    f = br.forms().next()
    request(f.click())

    print "Downloading all data"
    request(br.click_link(url_regex=re.compile(".*export-dialog$")))

    f = br.forms().next()
    f.find_control("exportFormat").items[-1].selected = True

    # chose the time range to download
    if not ('From' in opts and 'To' in opts):
        # real time data apparently isn't available
        now = datetime.datetime.now() - datetime.timedelta(days=2)
        then = now - datetime.timedelta(days=1)
        f['from'] = "%i/%i/%i" % (now.month, now.day, now.year)
        f['to'] = "%i/%i/%i" % (now.month, now.day, now.year)
    else:
        f['from'] = opts['From']
        f['to'] = opts['To']

    resp = request(f.click())

    # make a zipfile
    data = zipfile.ZipFile(StringIO(resp.read()))
    # and extract the contents
    rv = {}
    for name in data.namelist():
        if name.endswith("/"): continue
        print "extracting", name
        # with open(os.path.join(outdir, name), 'wb') as fp:
        # fp.write(data.read(name))
        
        # rv[name] = etree.XML(data.read(name))
        if opts.get('Type', 'electric') in name:
            data = data.read(name)
            return data
    return None
