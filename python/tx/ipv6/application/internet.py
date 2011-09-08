# coding: utf-8
# Copyright (c) 2001-2010 Twisted Matrix Laboratories.
# See LICENSE for details.

"""
See twisted/application/internet.py for details related to this module.

This module is part of the twistedpatch that attempts to provide IPv6 support
for Twisted without modifying the core Twisted files. The IPv6 patch is
applied at runtime and requires only minor modifications to your sources,
specifically to include support for this patch.

Be aware that this patch is neither supported nor endorsed by Twisted Matrix
Laboratories. Using this patch may break things. You have been warned.
"""

from twisted.application.internet import _AbstractClient
from twisted.application.internet import _AbstractServer as _TwistedAbstractServer
from twisted.application.internet import _VolatileDataService

class _AbstractServer (_TwistedAbstractServer):
    def _getPort (self):
        if self.reactor is None:
            from tx.ipv6.internet import reactor
        else:
            reactor = self.reactor
        return getattr(reactor, 'listen%s' % (self.method,))(*self.args,
                                                             **self.kwargs)
        
_doc={
'Client':
"""Connect to %(tran)s

Call reactor.connect%(method)s when the service starts, with the
arguments given to the constructor.
""",
'Server':
"""Serve %(tran)s clients

Call reactor.listen%(method)s when the service starts, with the
arguments given to the constructor. When the service stops,
stop listening. See twisted.internet.interfaces for documentation
on arguments to the reactor method.
""",
}
        
import new
for tran in 'TCP TCP6 UNIX SSL UDP UNIXDatagram Multicast'.split():
    for side in 'Server Client'.split():
        if tran == "Multicast" and side == "Client":
            continue
        base = globals()['_Abstract'+side]
        method = {'Generic': 'With'}.get(tran, tran)
        doc = _doc[side]%vars()
        klass = new.classobj(tran+side, (base,),
                             {'method': method, '__doc__': doc})
        globals()[tran+side] = klass
        
__all__ = (['TimerService', 'CooperatorService', 'MulticastServer'] +
           [tran+side
            for tran in 'Generic TCP UNIX SSL UDP UNIXDatagram'.split()
            for side in 'Server Client'.split()])