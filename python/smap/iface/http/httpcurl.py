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

import sys
import pycurl
import cStringIO as StringIO
import time
from threading import Thread
from Queue import Queue

from smap.util import json_decode

class ParserThread(Thread):
    """Parse the http results in parallel with getting them from the server
    """
    def __init__(self, parser):
        self.parser = parser
        self.q = Queue()
        self.ptime = 0
        self.rawlength = 0
        Thread.__init__(self)
    
    def run(self):
        self.result = []
        while True:
            next = self.q.get(True)
            if next == None: break
            (url, item) = next
            # print "parsing result for", url
            item.seek(0)
            tic = time.time()
            val = self.parser(item.read())
            self.ptime += (time.time() - tic)
            self.rawlength += item.tell()

            self.result.append((url, val))

    def add(self, url, pval):
        self.q.put_nowait((url, pval))

    def finish(self):
        self.q.put_nowait(None)
        self.join()
        return self.result

def mkrequest(c, spec):
    c.url = spec
    c.body = StringIO.StringIO()
    c.http_code = -1
    c.setopt(pycurl.URL, c.url)
    c.setopt(pycurl.WRITEFUNCTION, c.body.write)
    return c

def get(getspec, nconns=5, parser=json_decode, select_timeout=1.0, verbose=True):
    """get a list of urls, using a connection pool of up to nconn connections.
    apply "parser" to each of the results.

    Based on retriever-multi.py.
    """
    tic = time.time()
    parser_thread = ParserThread(parser)
    parser_thread.start()

    rv = []
    m = pycurl.CurlMulti()
    m.handles = []
    for spec in xrange(nconns):
        c = pycurl.Curl()
        c.fp = None
        c.setopt(pycurl.FOLLOWLOCATION, 1)
        c.setopt(pycurl.MAXREDIRS, 5)
        c.setopt(pycurl.CONNECTTIMEOUT, 30)
        c.setopt(pycurl.TIMEOUT, 300)
        c.setopt(pycurl.NOSIGNAL, 1)
        m.handles.append(c)

    freelist = m.handles[:]
    num_processed, num_urls = 0, len(getspec)
    while num_processed < num_urls:
        while getspec and freelist:
            spec = getspec.pop(0)
            c = freelist.pop()
            mkrequest(c, spec)
            m.add_handle(c)

        while 1:
            ret, num_handles = m.perform()
            if ret != pycurl.E_CALL_MULTI_PERFORM: 
                break

        while 1:
            num_q, ok_list, err_list = m.info_read()
            for c in ok_list:
                # print "Success:", c.url, c.getinfo(pycurl.EFFECTIVE_URL)
                # print "Success:", c.url, c.getinfo(pycurl.EFFECTIVE_URL)
                parser_thread.add(c.url, c.body)
                c.fp = None
                c.body = None
                m.remove_handle(c)
                freelist.append(c) 

            for c, errno, errmsg in err_list:
                m.remove_handle(c)
                print "Failed: ", c.url, errno, errmsg
                freelist.append(c)

            num_processed += len(ok_list) + len(err_list)
            if verbose:
                print >>sys.stderr, str(num_processed) + '/' + str(num_urls) +  '\r'
            if num_q == 0:
                break

        m.select(select_timeout)
    print

    for c in m.handles:
        c.close()
    m.close()
    dlend = time.time()

    rv = parser_thread.finish()
    toc = time.time()
    print """downloaded %ib from %i urls in %.03fs (%.03fMB/s download: %.03fs, parse: %03fs)""" % \
        (parser_thread.rawlength, 
         
         len(rv), toc - tic, 
         float(parser_thread.rawlength) / ((dlend - tic) * 1e6),
         dlend - tic, parser_thread.ptime)
    return rv
