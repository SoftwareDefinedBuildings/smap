#! -*- python -*-
"""
Copyright (c) 2014 Regents of the University of California
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
"""Methods for discovering network devices based on dhcp

@author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
"""
import re
import collections
import subprocess
from netifaces import ifaddresses

from twisted.internet import reactor, protocol, defer
from twisted.protocols.basic import LineReceiver
from smap.iface import tail

import util

class DhcpTailDiscoverySource(object):
    """Discover new devices by tailing syslog

    It should call the discovery callback with a Device instance every
    time there is a potentially new device discovered.
    """
    def __init__(self, discovered_callback, syslog):
        self.discovered_callback = discovered_callback
        self.syslog = syslog
        self.tailer = tail.FollowTail(self.syslog, seekend=False)
        self.tailer.lineReceived = self.syslogLineReceived

    def syslogLineReceived(self, line):
        if line.find("DHCPOFFER") < 0: return
        # try to find any DHCPOFFERS made
        # DHCPOFFER on 10.4.10.113 to 54:26:96:d7:84:6d (Michaels-MBP-3) via eth1
        m = re.match(".*DHCPOFFER on ((\d{1,3}\.){3}\d{1,3}) to ((\w{2}:){5}\w{2}) \((.*)\) via (.*)\W*$", line)
        if m:
            ip, _, mac, __, name, iface = m.groups(0)
        else:
            m = re.match(".*DHCPOFFER on ((\d{1,3}\.){3}\d{1,3}) to ((\w{2}:){5}\w{2}) via (.*)$", line)
            if m:
                name = None
                ip, _, mac, __, iface = m.groups(0)
            else:
                return

        dev = util.Device(ip, mac, name, iface)
        self.discovered_callback(dev)

    def start(self):
        self.tailer.start()

    def stop(self):
        self.tailer.stop()

class DhcpSnoopDiscovery(protocol.ProcessProtocol, LineReceiver):
    delimiter = "\n"

    def __init__(self, discovered_callback, iface, dhcpdump_path = '/usr/local/bin/dhcpdump'):
        self.discovered_callback = discovered_callback
        self.parsestate = collections.defaultdict(set)
        self.iface = iface
        self.outReceived = self.dataReceived
        self.dhcpdump_path = dhcpdump_path
        self.arp_seen = set()
        self.get_arp()

    def start(self):
        path = self.dhcpdump_path
        reactor.spawnProcess(self, path, [path, "-i", self.iface])
        # path = "/bin/cat"
        # reactor.spawnProcess(self, path, [path, "dhcp.log"])
        self.transport.disconnecting = False

    def stop(self):
        pass

    def errReceived(self, data):
        print data

    def lineReceived(self, line):
        chars = set(line.strip())
        if len(chars) == 1 and chars.pop() == '-':
            self.discover()
            self.parsestate = collections.defaultdict(set)
            return

        m = re.match("\W*(\w*): (.*)$", line)
        if not m: return
        k, v = m.groups(0)
        self.parsestate[k].add(v)

    def get_arp(self):
        local_ip = ifaddresses(self.iface)[2][0]['addr']
        ip_range = '.'.join(local_ip.split('.')[:-1] + ['0/24'])
        try:
            arp_output = subprocess.check_output(['arp-scan', ip_range])
            for line in arp_output.split('\n'):
                m = re.match("((\d{1,3}\.){3}\d{1,3})\\t((\w{1,2}:){5}\w{1,2})\\t(.*)", line)
                if not m:
                    continue
                g = m.groups(0)
                s_ip, s_mac, hname = g[0],g[2],g[4]
                if s_mac in self.arp_seen or hname == '(Unknown)':
                    continue
                else:
                    self.arp_seen.add(s_mac)
                print "Detected", s_ip, s_mac, hname, self.iface, "via arpscan"
                dev = util.Device(s_ip, s_mac, hname, self.iface)
                self.discovered_callback(dev)
        except subprocess.CalledProcessError:
            print 'Probably an invalid ip_range:',ip_range
            return
        except OSError:
            print 'Make sure arp-scan is installed'
            return
        except Exception as e:
            print e
            return


    def discover(self):
        if not 'BOOTPREQUEST' in self.parsestate['OP'].pop(): return
        ipstr = self.parsestate['IP'].pop()

        # see if there's a host name option
        hname = None
        for v in self.parsestate["OPTION"]:
            if "Host name" in v:
                hname = v[v.index("Host name")+9:].strip()

        # also grab the ip and mac if available
        m = re.match("((\d{1,3}\.){3}\d{1,3}) \(((\w{1,2}:){5}\w{1,2})\) "
                     "> ((\d{1,3}\.){3}\d{1,3}) \(((\w{1,2}:){5}\w{1,2})\)", ipstr)
        if not m: return
        g = m.groups(0)
        s_ip, s_mac = g[0], g[2]
        if s_ip == '0.0.0.0':
            print "Detected null source address... arp required?", s_mac
            self.get_arp()
        else:
            print "Detected", s_ip, s_mac, hname, self.iface, "via snooping"
            dev = util.Device(s_ip, s_mac, hname, self.iface)
            self.discovered_callback(dev)

if __name__ == '__main__':
    d = DhcpSnoopDiscovery(lambda x: x, "eth1")
    d.start()
    reactor.run()
    # for l in open("dhcp.log", "r").readlines():
    #     d.lineReceived(l)
