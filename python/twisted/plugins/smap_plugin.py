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
from twisted.application.service import IServiceMaker
from twisted.application import internet
from twisted.internet import reactor
from twisted.application.service import MultiService

from smap import core, loader, smapconf
from smap.server import getSite
from smap.util import buildkv

try:
    from smap.ssl import SslServerContextFactory
except ImportError:
    pass

try:
    from smap.bonjour import broadcast
except ImportError:
    print >>sys.stderr, "sMAP: pybonjour not available"
    def broadcast(*args):
        pass


def make_dns_meta(inst):
    root = inst.lookup("/")
    m = {"uuid": str(inst.root_uuid)}
    if root and "Metadata" in root:
        m.update(dict(buildkv("Metadata", root["Metadata"])))
    return m

class Options(usage.Options):
    optParameters = [["data-dir", "d", None, "directory for data"],
                     ["port", "p", None, "service port number"],
                     ["sslport", "s", None, "ssl port number"],
                     ["key", "k", None, "ssl server key"],
                     ["cert", "c", None, "ssl crl list"]]

    def parseArgs(self, conf):
        self['conf'] = conf
        if not os.access(self['conf'], os.R_OK):
            print >>sys.stderr, "ERROR: no such configuration file: " + self['conf']
            sys.exit(1)

class SmapServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "smap"
    description = "A sMAP server"
    options = Options

    def makeService(self, options):
        if options['data-dir'] != None:
            if not os.access(options['data-dir'], os.X_OK | os.W_OK):
                raise core.SmapException("Cannot access " + options['data-dir'])
            smapconf.SERVER['DataDir'] = options['data-dir']

        inst = loader.load(options['conf'])
        smapconf.start_logging()
        # override defaults with command-line args
        smapconf.SERVER.update(dict([(k.lower(), v) for (k, v) in
                                     options.iteritems() if v != None]))

        if 'SuggestThreadPool' in smapconf.SERVER:
            reactor.suggestThreadPoolSize(int(smapconf.SERVER['SuggestThreadPool']))

        inst.start()
        reactor.addSystemEventTrigger('before', 'shutdown', inst.stop)

        site = getSite(inst, docroot=smapconf.SERVER['docroot'])
        service = MultiService()
        # add HTTP and HTTPS servers to the twisted multiservice

        meta = make_dns_meta(inst)

        if 'port' in smapconf.SERVER:
            service.addService(internet.TCPServer(int(smapconf.SERVER['port']), site))
            broadcast(reactor, "_smap._tcp", int(smapconf.SERVER['port']), 'sMAP Server', meta)
        if 'sslport' in smapconf.SERVER:
            service.addService(internet.SSLServer(int(smapconf.SERVER['sslport']), 
                                                  site, 
                                                  SslServerContextFactory(smapconf.SERVER)))

        return service

serviceMaker = SmapServiceMaker()

