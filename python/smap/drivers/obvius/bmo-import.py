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
import time
import datetime

from twisted.internet import reactor, defer
from twisted.python import log

from smap import loader
from smap.drivers.obvius import bmo
from smap.contrib import dtutil

# day to start import at
startdt = dtutil.strptime_tz("09 01 2011", "%m %d %Y")
enddt = startdt + datetime.timedelta(days=1)
# number of days to request
days = 3

def next_day():
    global startdt
    global enddt
    global inst
    global days

    print "\n\nSTARTING DAY (%i remaining)\n" % days
    tasks = []
    for d in inst.drivers.itervalues():
        if isinstance(d, bmo.BMOLoader):
            tasks.append(d.update(startdt, enddt))

    startdt = startdt + datetime.timedelta(days=1)
    enddt = startdt + datetime.timedelta(days=1)
    d = defer.DeferredList(tasks)
    d.addCallback(lambda _: inst._flush())
    return d

def do_next_day(*args):
    global days
    if days > 0:
        days -= 1
        d = next_day()
        d.addCallback(do_next_day)
        return d
    else:
        pass
    #reactor.stop()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "\n\t%s <conf>\n" % sys.argv[0]

    log.startLogging(sys.stdout)

    inst = loader.load(sys.argv[1])
    do_next_day()
    reactor.run()
