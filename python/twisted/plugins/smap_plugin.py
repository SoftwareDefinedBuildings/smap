
import os
import sys

from zope.interface import implements

from twisted.python import usage
from twisted.plugin import IPlugin
from twisted.application.service import IServiceMaker
from twisted.application import internet

from smap import core, loader, smapconf
from smap.server import getSite

class Options(usage.Options):
    optParameters = [["data-dir", "d", None, "directory for data"],
                     ["port", "p", None, "service port number"]]

    def parseArgs(self, conf):
        self['conf'] = conf


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
        if options["port"] != None:
            port = options["port"]
        else:
            port = smapconf.SERVER['Port']
        inst.start()

        return internet.TCPServer(int(port), getSite(inst))

serviceMaker = SmapServiceMaker()
