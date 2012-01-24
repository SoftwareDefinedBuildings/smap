
import os
import sys

from zope.interface import implements

from twisted.python import usage
from twisted.plugin import IPlugin
from twisted.application.service import IServiceMaker
from twisted.application import internet
from twisted.internet import reactor, ssl
from twisted.application.service import MultiService
from twisted.enterprise import adbapi

from smap.archiver import settings
from smap.subscriber import subscribe

class Options(usage.Options):
    optParameters = [["port", "p", None, "service port number"]]
    optFlags = [["subscribe", "s", "subscribe to sources"]]

    def parseArgs(self, conf):
        self['conf'] = conf

class ArchiverServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "smap-archiver"
    description = "A sMAP archiver"
    options = Options

    def makeService(self, options):
        # we better add 
        reactor.suggestThreadPoolSize(30)

        if options['conf']:
            settings.load(options['conf'])
        if options['port']:
            port = int(options['port'])
        else:
            port = int(settings.MY_PORT)

        cp = adbapi.ConnectionPool(settings.DB_MOD, # 'MySQLdb', 
                                   host=settings.DB_HOST,
                                   database=settings.DB_DB,
                                   user=settings.DB_USER,
                                   password=settings.DB_PASS,
                                   cp_min=5, cp_max=15)

        if options['subscribe']:
            subscribe(cp, settings)

        site = getSite(cp)
        service = internet.TCPServer(port, site)
        return service

# try this; since we may be missing psycopg2 or readingdb, we may not
# be able to do this and so won't be able to provide an archiver.
# However, since this plugin gets installed for all smap installs,
# just fail silently rather than print out a bunch of warnings.
try:
    from smap.archiver.server import getSite
except ImportError:
    pass
else:
    serviceMaker = ArchiverServiceMaker()
