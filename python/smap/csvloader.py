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

# this is the twisted event loop
from twisted.internet import reactor

# use this to get a smap source in one line
import loader

# autoflush means that we don't call flush on a timer
s = loader.load('default.ini', autoflush=None)


CHUNKSIZE=1000
i = 0
def fail(err):
    print "Received error while delivering reports"
    reactor.stop()
    
def do_add(*args):
    global i
    global CHUNKSIZE
    if i > 10000:
        reactor.stop()
    else:
        # publish a bunch of data
        for v in xrange(i*CHUNKSIZE, i*CHUNKSIZE+CHUNKSIZE):
            s.get_timeseries('/sensor0')._add(0, v)
        i += 1
        print "flush", CHUNKSIZE
        
        # then flush. we'll get a callback once we've sent it to all
        # of the destinations
        d = s.reports._flush()
        d.addCallback(do_add)
        d.addErrback(fail)

reactor.callFromThread(do_add)
reactor.run()
