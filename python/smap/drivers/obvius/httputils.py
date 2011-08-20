
import os
import urllib2
import urlparse
from binascii import hexlify
from BeautifulSoup import BeautifulSoup as bs
import hashlib

urllib2.install_opener(urllib2.build_opener())

CACHEDIR='cache'

def load_html(url, cache=True, AUTH=None):
    if not os.access(CACHEDIR, os.W_OK):
        os.makedirs(CACHEDIR)
    name = hashlib.md5()
    name.update(url)
    cachename = os.path.join(CACHEDIR,  hexlify(name.digest()))
    if os.access(cachename, os.W_OK | os.R_OK) and cache:
        with open(cachename, 'r') as fp:
            return bs(fp.read())
    else: 
        try:
            if AUTH != None:
                mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
                url_p = urlparse.urlparse(url)
                mgr.add_password(None, url_p.netloc, AUTH[0], AUTH[1])
                handler = urllib2.HTTPBasicAuthHandler(mgr)
                opener = urllib2.build_opener(handler)
                pagefp = opener.open(url, timeout=15)
            else:
                pagefp = urllib2.urlopen(url, timeout=10) 

            data = pagefp.read()
            pagefp.close();
        except Exception, e:
            print e
            return None

        with open(cachename, 'w') as cachefp:
            cachefp.write(data)
            return bs(data)

