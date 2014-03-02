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
import sys

from zope.interface import implements

from twisted.python import usage
from twisted.plugin import IPlugin
from twisted.application.service import IServiceMaker, MultiService
from twisted.application import internet
from twisted.internet import reactor, ssl
from twisted.application.service import MultiService
from twisted.enterprise import adbapi

class Options(usage.Options):
    optParameters = [["port", "p", None, "service port number"]]
    optFlags = [["subscribe", "s", "subscribe to sources"],
                ["memdebug", "m", "print memory debugging information"]]

    def parseArgs(self, conf):
        self['conf'] = conf

class ArchiverServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "smap-archiver"
    description = "A sMAP archiver"
    options = Options


    def makeService(self, options):
        if options['conf']:
            settings.conf = settings.load(options['conf'])

        # we better add 
        reactor.suggestThreadPoolSize(settings.conf['threadpool size'])

        if options['memdebug']:
            from twisted.internet import task
            import objgraph
            import gc
            def stats():
                print gc.collect()
                print
                print '\n'.join(map(str, objgraph.most_common_types(limit=10)))
            task.LoopingCall(stats).start(2)

        cp = adbapi.ConnectionPool(settings.conf['database']['module'],
                                   host=settings.conf['database']['host'],
                                   database=settings.conf['database']['db'],
                                   user=settings.conf['database']['user'],
                                   password=settings.conf['database']['password'],
                                   port=settings.conf['database']['port'],
                                   cp_min=5, cp_max=30,
                                   cp_reconnect=True)

        if options['subscribe']:
            subscribe(cp, settings)


        # create a single republisher to send the data out on
        repub = republisher.ReResource(cp)
        service = MultiService()
        for svc in settings.conf['server']:
            scfg = settings.conf['server'][svc]
            site = getSite(cp, 
                           resources=scfg['resources'],
                           repub=repub)
            if not len(scfg['ssl']) > 1:
                service.addService(internet.TCPServer(scfg['port'],
                                                      site,
                                                      interface=scfg['interface']))
            else:
                service.addService(internet.SSLServer(scfg['port'],
                                                      site,
                                                      SslServerContextFactory(scfg['ssl']),
                                                      interface=scfg['interface']))

        return service

# try this; since we may be missing psycopg2 or readingdb, we may not
# be able to do this and so won't be able to provide an archiver.
# However, since this plugin gets installed for all smap installs,
# just fail silently rather than print out a bunch of warnings.
try:
    from smap.archiver import settings, republisher
    from smap.subscriber import subscribe
    from smap.ssl import SslServerContextFactory
    from smap.archiver.server import getSite
except ImportError:
    pass
else:
    serviceMaker = ArchiverServiceMaker()
