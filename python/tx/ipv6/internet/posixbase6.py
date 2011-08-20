#!/usr/bin/env python
# coding: utf-8
# Copyright (c) 2001-2010 Twisted Matrix Laboratories.
# See LICENSE for details.
#
# Exceedingly minor changes by B. A. Shelton, zancarius@gmail.com
# !!! Do not blame Twisted Matrix Laboratories if using this monkey patch breaks
#     your application. !!!
#
# This file is based entirely on the twisted.internet.posixbase module and now
# includes a definition for listenTCP6. This function definition is monkey
# patched into the reactor and can be used simultaneously with listenTCP().

from tx.ipv6.internet import tcp6, udp6

def listenTCP6 (self, port, factory, backlog=50, interface=''):
    p = tcp6.Port6(port, factory, backlog, interface, self)
    p.startListening()
    return p

def listenUDP6 (self, port, protocol, interface='', maxPacketSize=8192):
    p = udp6.Port6(port, protocol, interface, maxPacketSize, self)
    p.startListening()
    return p
