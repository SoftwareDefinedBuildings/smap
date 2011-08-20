#!/usr/bin/env python
# coding: utf-8
# Copyright (c) 2001-2010 Twisted Matrix Laboratories.
# See LICENSE for details.
#
# Exceedingly minor changes by B. A. Shelton, zancarius@gmail.com
# !!! Do not blame Twisted Matrix Laboratories if using this monkey patch breaks
#     your application. !!!
#
# This file is based entirely on the twisted.internet.tcp module as it ships
# with Twisted v10.1. Only very minor changes have been made, specifically
# all references to TCP and UDP have been moved to TCP6/UDP6 and all IPv4
# references in the comments and the code have been moved to IPv6. Socket
# address families have been bumped to socket.AF_INET6.
#
# Class changes in this file are implemented by subclassing the appropriate
# Twisted classes. Note that the Port implementation in this module (Port6)
# forces the socket to listen only on IPv6 connections; this should allow you
# to use IPv4 and IPv6 simultaneously.

import socket
import sys

from twisted.python.runtime import platformType

from twisted.internet import abstract
from twisted.internet import base
from twisted.internet import tcp
from tx.ipv6.internet import address6 as address

# Twisted imports for overrides.
import twisted.internet.tcp

class BaseClient(twisted.internet.tcp.BaseClient):
    """A base class for client TCP (and similiar) sockets.
    """
    addressFamily = socket.AF_INET6
    socketType = socket.SOCK_STREAM

    def resolveAddress(self):
        if abstract.isIPAddress(self.addr[0]):
            self._setRealAddress(self.addr[0])
        else:
            d = self.reactor.resolve(self.addr[0])
            d.addCallbacks(self._setRealAddress, self.failIfNotConnected)

    def _setRealAddress(self, address):
        self.realAddress = (address, self.addr[1])
        self.doConnect()

class Server(twisted.internet.tcp.Server):
    """
    Serverside socket-stream connection class.

    This is a serverside network connection transport; a socket which came from
    an accept() on a server.
    """

    def getHost(self):
        """Returns an IPv6Address.

        This indicates the server's address.
        """
        return address.IPv6Address('TCP6', *(self.socket.getsockname() + ('INET6',)))

    def getPeer(self):
        """Returns an IPv6Address.

        This indicates the client's address.
        """
        return address.IPv6Address('TCP6', *(self.client + ('INET6',)))

class Port6(tcp.Port):

    addressFamily = socket.AF_INET6
    socketType = socket.SOCK_STREAM

    # Do not remove this. You will break something.
    transport = Server

    def createInternetSocket(self):
        s = base.BasePort.createInternetSocket(self)
        if platformType == "posix" and sys.platform != "cygwin":
            # Required: Forces listenTCP6 to listen exclusively on IPv6 addresses.
            # See: http://www.velocityreviews.com/forums/t328345-ipv6-question.html
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s

    def _buildAddr(self, (host, port, flowinfo, scopeid)):
        return address._ServerFactoryIPv6Address('TCP6', host, port, flowinfo, scopeid)

    def getHost(self):
        """Returns an IPv6Address.

        This indicates the server's address.
        """
        # IPv6 returns: (address, port, flowinfo, scopeid) for socket.getsockname()
        return address.IPv6Address('TCP6', *(self.socket.getsockname() + ('INET6',)))
