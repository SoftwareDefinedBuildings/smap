
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
