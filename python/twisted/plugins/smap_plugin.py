
import sys

from zope.interface import implements

from twisted.python import usage
from twisted.plugin import IPlugin
from twisted.application.service import IServiceMaker
from twisted.application import internet

from smap import core, loader, smapconf
from smap.server import getSite

class Options(usage.Options):
    optParameters = [["conf", "c", None, "sMAP configuration file"],
                     ["port", "p", None, "service port number"]]

class SmapServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "smap"
    description = "A sMAP server"
    options = Options

    def makeService(self, options):
        if options['conf'] == None:
            print >>sys.stderr, "FATAL: Must provide a sMAP config file (use -c)"
            sys.exit(1)

        inst = loader.load(options['conf'])
        if options["port"] != None:
            port = options["port"]
        else:
            port = smapconf.SERVER['Port']
        inst.start()

        return internet.TCPServer(int(port), getSite(inst))

serviceMaker = SmapServiceMaker()
