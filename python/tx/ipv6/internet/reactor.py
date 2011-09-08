#!/usr/bin/env python
# coding: utf-8

'''
This module initializes and installs the Twisted reactor and then conditionally
monkey patches it if the listenTCP6() method has not already been defined. This
may break when using newer versions of Twisted and will likely not work in the
circumstance that IPv6 support is finally added to Twisted. Read the release
notes for your version of Twisted to determine whether IPv6 is supported. Note
that Twisted will most likely implement IPv6 as an extension to listenTCP() and
friends instead of implementing additional methods. Use of this patch is
unsupported.

Also, this patch will probably break things.

It should be possible to use additional reactors with this patch. For example,
if you wish to use epoll instead of the standard select reactor, the following
should work if you have a fairly recent Linux-based platform:

from twisted.internet import epollreactor
epollreactor.install()
from twistedpatch.internet import reactor # Will now use epollreactor

kqueue should work similarly.

Address resolution will NOT work and hasn't been implemented, so you may need
to use Python's socket module where appropriate.
'''

import sys
del sys.modules['tx.ipv6.internet.reactor']
import sys # Required to work around some import-related funkiness.  
from twisted.internet import selectreactor

reactor = selectreactor.SelectReactor()

import tx.ipv6.internet
assert not sys.modules.has_key('tx.ipv6.internet.reactor'), \
       "reactor already installed"
if sys.modules.has_key("twisted.internet.reactor"):
    reactor = sys.modules["twisted.internet.reactor"]

tx.ipv6.internet.reactor = reactor
sys.modules['tx.ipv6.internet.reactor'] = reactor

import types
from tx.ipv6.internet import tcp6, udp6
from tx.ipv6.internet import posixbase6

if not hasattr(reactor, "listenTCP6"):
    reactor.listenTCP6 = types.MethodType(posixbase6.listenTCP6, reactor, reactor.__class__)

if not hasattr(reactor, "listenUDP6"):
    reactor.listenUDP6 = types.MethodType(posixbase6.listenUDP6, reactor, reactor.__class__)
