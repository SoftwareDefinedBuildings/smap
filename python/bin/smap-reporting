#!/usr/bin/python
# -*- python -*-
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
import optparse
import pprint

from twisted.internet import reactor, defer
from twisted.python import log

from smap import reporting
from smap import util

parser = optparse.OptionParser()
parser.add_option('-d', '--deliver', dest='deliver', action='store_true',
                  default=False, help='Deliver undelivered data')
parser.add_option('-v', '--verbose', dest='verbose', action='store_true',
                  default=False, help='Dump pending data verbosely')
parser.add_option('-e', '--edit', dest='uuid', type='string',
                  default=False, help='report uuid instance to edit')
parser.add_option('-l', '--location', dest='location', type='string',
                  default=False, help='different report location')
parser.add_option('-t', '--truncate', dest='truncate', type='int',
                  default=False, help='truncate log')
opts, args = parser.parse_args()
log.startLogging(sys.stdout)

deferList = []
for rf in args:
    rpt = util.pickle_load(rf)

    print '=' * 60
    print " ReportFile:", rf
    print
    for r in rpt:
        if opts.uuid == str(r['uuid']):
            if opts.location:
                print opts.location
                r['ReportDeliveryLocation'] = [opts.location]
            #if opts.truncate:
                # print "Truncating to", opts.truncate, "log entries"
                #del r['PendingData'][opts.truncate:]
        for k in ['uuid', 'ReportDeliveryLocation', 'ReportResource', 'MinPeriod', 'MaxPeriod']:
            print ' ', k, ':', r[k]
        print "  Log Length:", len(r['PendingData'])
        print
    if opts.uuid:
        print "saving edited report"
        util.pickle_dump(rf, rpt)

    if opts.deliver:
        rinst = reporting.Reporting(None, reportfile=rf, autoflush=None)
        deferList.append(rinst._flush(force=True))

if opts.deliver and len(filter(lambda x: x != None, deferList)) > 0:
    d = defer.DeferredList(deferList, fireOnOneErrback=True, consumeErrors=True)
    d.addBoth(lambda _: reactor.stop())
    reactor.run()
