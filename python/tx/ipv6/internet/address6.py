#!/usr/bin/env python
# coding: utf-8
# Copyright (c) 2001-2010 Twisted Matrix Laboratories.
# See LICENSE for details.
#
# Exceedingly minor changes by B. A. Shelton, zancarius@gmail.com
# !!! Do not blame Twisted Matrix Laboratories if using this monkey patch breaks
#     your application. !!!
#
# This file is based entirely on the twisted.internet.address module as it ships
# with Twisted v10.1. Only very minor changes have been made, specifically
# all references to TCP and UDP have been moved to TCP6/UDP6 and all IPv4
# references in the comments and the code have been moved to IPv6.
#
# New class members have been added to support flowinfo and scopeid as returned
# from socket.getsockname() on an IPv6 socket.

import warnings, os

from zope.interface import implements

from twisted.internet.interfaces import IAddress

class IPv6Address(object):
    """
    Object representing an IPv6 socket endpoint. Based on the Twisted
    twisted.internet.address.IPv4Address definition.

    @ivar type: A string describing the type of transport, either 'TCP' or 'UDP'.
    @ivar host: A string containing the dotted-quad IP address.
    @ivar port: An integer representing the port number.
    """

    implements(IAddress)

    def __init__(self, type, host, port, flowinfo, scopeid, _bwHack = None):
        assert type in ('TCP6', 'UDP6')
        self.type = type
        self.host = host
        self.port = port
        self.flowinfo = flowinfo
        self.scopeid = scopeid
        self._bwHack = _bwHack

    def __eq__(self, other):
        if isinstance(other, tuple):
            return tuple(self) == other
        elif isinstance(other, IPv6Address):
            a = (self.type, self.host, self.port, self.flowinfo, self.scopeid)
            b = (other.type, other.host, other.port, self.flowinfo, self.scopeid)
            return a == b
        return False

    def __repr__(self):
        return 'IPv6Address(%s, %r, %d, %d, %d)' % (self.type, self.host, self.port, self.flowinfo, self.scopeid)

class _ServerFactoryIPv6Address(IPv6Address):
    """Backwards compatability hack. Just like IPv6Address in practice."""

    def __eq__(self, other):
        if isinstance(other, tuple):
            warnings.warn("IPv6Address.__getitem__ is deprecated.  Use attributes instead.",
                          category=DeprecationWarning, stacklevel=2)
            return (self.host, self.port, self.flowinfo, self.scopeid) == other
        elif isinstance(other, IPv6Address):
            a = (self.type, self.host, self.port, self.flowinfo, self.scopeid)
            b = (other.type, other.host, other.port, self.flowinfo, self.scopeid)
            return a == b
        return False