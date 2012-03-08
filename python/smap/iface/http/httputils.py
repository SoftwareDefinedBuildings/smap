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
"""
@author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
"""

import os
import urllib2
import urlparse
from binascii import hexlify
from BeautifulSoup import BeautifulSoup as bs
import hashlib
import json

urllib2.install_opener(urllib2.build_opener())

CACHEDIR='cache'

def load_http(url, cache=False, auth=None, data=None, as_fp=False):
    name = hashlib.md5()
    name.update(url)
    cachename = os.path.join(CACHEDIR,  hexlify(name.digest()))
    if os.access(cachename, os.W_OK | os.R_OK) and cache and not data:
        if not os.access(CACHEDIR, os.W_OK):
            os.makedirs(CACHEDIR)
        with open(cachename, 'r') as fp:
            if as_fp:
                return fp
            else:
                return fp.read()
    else: 
        try:
            if auth != None:
                mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
                url_p = urlparse.urlparse(url)
                mgr.add_password(None, url_p.netloc, auth[0], auth[1])
                handler = urllib2.HTTPBasicAuthHandler(mgr)
                opener = urllib2.build_opener(handler)
                req = urllib2.Request(url, data=data)
                pagefp = opener.open(req, timeout=15)
            else:
                pagefp = urllib2.urlopen(url, timeout=10) 

            if as_fp:
                return pagefp
            else:
                data = pagefp.read()
                pagefp.close();
                return data
        except Exception, e:
            print e
            return None

        if cache and not data:
            with open(cachename, 'w') as cachefp:
                cachefp.write(data)
                return data

def load_html(url, **kwargs):
    return bs(load_http(url, **kwargs))

def get(urls, **kwargs):
    v = map(lambda x: load_http(x, **kwargs), urls)
    return zip(urls, map(json.loads, v))
