

import pybonjour

from twisted.internet.interfaces import IReadDescriptor
from twisted.internet.defer import Deferred
from zope import interface
from twisted.python import log

class BonjourServiceDescriptor(object):
    interface.implements(IReadDescriptor)
    def __init__(self, sdref):
        self.sdref = sdref

    def doRead(self):
        pybonjour.DNSServiceProcessResult(self.sdref)

    def fileno(self):
        return self.sdref.fileno()

    def logPrefix(self):
        return "bonjour"

    def connectionLost(self, reason):
        self.sdref.close()

def broadcast(reactor, regtype, port, name=None, records={}):
    def _callback(sdref, flags, errorCode, name, regtype, domain):
        if errorCode == pybonjour.kDNSServiceErr_NoError:
            d.callback((sdref, name, regtype, domain))
        else:
            d.errback(errorCode)

    d = Deferred()
    sdref = pybonjour.DNSServiceRegister(name=name,
                                         regtype=regtype,
                                         port=port,
                                         callBack=_callback)
    recs = pybonjour.TXTRecord()
    for k, v in records.iteritems():
        recs[k] = str(v)
    pybonjour.DNSServiceAddRecord(sdref, 
                                  rrtype=pybonjour.kDNSServiceType_TXT,
                                  rdata=str(recs))

    reactor.addReader(BonjourServiceDescriptor(sdref))
    return d

