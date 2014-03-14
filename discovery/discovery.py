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
"""
@author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
"""

import os
import re
import operator
import xml.etree.ElementTree as ET
import ConfigParser
import subprocess

from twisted.internet import reactor, protocol, defer
from twisted.internet.utils import getProcessOutputAndValue

from smap.driver import SmapDriver

import dhcp
import util

# number of seconds to wait between detecting a device and scanning it.
DETECT_SCAN_WAIT = 1


class XmlProcessProtocol(protocol.ProcessProtocol):
    def __init__(self, done):
        self.data = []
        self.done = done
    def outReceived(self, data):
        self.data.append(data)
    def errReceived(self, data):
        print data
    def processEnded(self, reason):
        try:
            self.done.callback(ET.fromstring(''.join(self.data)))
        except ET.ParseError, e:
            self.done.errback(e)


class DiscoveryDriver(SmapDriver):
    """sMAP Driver which watches for new drivers on the subnet and
    produces new sMAP config files.
    """
    def setup(self, opts):
        # self.lease_file = opts.get("lease_file", "/var/lib/dhcp/dhcpd.leases")
        self.config_repo = opts.get("config_repo", '.')
        self.db = {}
        self._driverport = 1234
        self._nmap_path = opts.get('nmap_path','/usr/bin/nmap')
        self.discovery_sources = [
            # dhcp.DhcpTailDiscoverySource(self.update_device, opts.get("syslog", "/var/log/syslog")),
            dhcp.DhcpSnoopDiscovery(self.update_device, opts.get("dhcp_iface"), opts.get("dhcpdump_path")),
            ]
    @property
    def driverport(self):
        self._driverport += 1
        return self._driverport

    def start(self):
        map(operator.methodcaller("start"), self.discovery_sources)

    def stop(self):
        map(operator.methodcaller("stop"), self.discovery_sources)

    def update_device(self, dev):
        if dev.key() in self.db:
            # print "Device already discovered:", dev
            dev = self.db[dev.key()]
        else:
            self.db[dev.key()] = dev

        if not dev.last_discovery and not dev.scan_pending:
            dev.scan_pending = True
            print "Scheduling device scan", dev
            reactor.callLater(DETECT_SCAN_WAIT, self.scan_device, dev)

    def error(self, *args):
        print 'Error:',args[1].ip, args[1].mac

    def scan_device(self, dev):
        # if dev.ip != '10.4.10.100': return
        d = defer.Deferred()
        pp = XmlProcessProtocol(d)
        print "Starting scan of", dev.ip
        reactor.spawnProcess(pp, self._nmap_path, ['nmap', "--script=scripts", '-oX', '-', dev.ip])
        d.addCallbacks(self.process_scan_results, errback=self.error, callbackArgs=(dev,), errbackArgs=(dev,))
        d.addCallback(self.register_services)

    def process_scan_results(self, root, dev):
        # root.find('host')
        services = []
        print "device scan of", dev.ip, "complete ...",
        host = root.find("host") if root else None
        if root == None or host == None:
            print "no output found... error?"
            return []
        for port in host.find("ports"):
            for script in port.findall("script"):
                conf = {}
                for c in script:
                    conf[c.attrib['key']] = c.text
                if len(conf):
                    services.append(util.Service(dev, script.attrib['id'], conf))
        print len(services), "sMAP service(s) found:"
        if len(services): print "\t" + (" ".join((s.script for s in services)))
        return services

    def register_services(self, services):
        configs = map(self.update_config, services)
        map(self.start_service, services)
        #for svc, d in zip(services, map(self.push_config, configs)):
        #    d.addCallback(self.start_service, svc)

    def update_config(self, service):
        strname = service.script + "-" + service.dev.ip
        path = os.path.join(self.config_repo, 'driverconfigs', strname + '.ini')
        print "\tupdating config", path
        with open(path, 'w') as fp:
            print >>fp, """
[/]
Port = 8080
uuid = %(uuid)s

[/%(strname)s]
uuid = %(uuid)s
""" % {'strname': strname, 'uuid': str(self.uuid(service.dev.key()))}
            for k, v in service.conf.iteritems():
                print >>fp, k.replace("__", "/"), "=", v
        return path

    def push_config(self, config_file):
        print "committing changes to", config_file
        push_script = """
git add %s;
git commit -m "Commit by autodiscovery process";
git push origin master""" % config_file
        d = getProcessOutputAndValue("/bin/sh", args=["-c", push_script], env={"PATH": "/usr/bin"}, path=self.config_repo)
        def check_commit((stdout, stderr, code)):
            if code != 0:
                print "error: ", stderr
                # make sure to kill any callback chains
                raise util.PushError(stderr)
        d.addCallback(check_commit)
        return d

    def start_service(self, service):
        strname = service.script + "-" + service.dev.ip
        c = ConfigParser.RawConfigParser()
        c.read('supervisord.conf')
        # remove old config section
        c.remove_section('program:{0}'.format(strname))
        # add new section
        c.add_section('program:{0}'.format(strname))
        # use custom port and custom pidfile
        c.set('program:{0}'.format(strname),'command','twistd --pidfile={strname}.pid -n smap -p {port} driverconfigs/{strname}.ini'.format(strname=strname, port=self.driverport))
        c.write(open('supervisord.conf','w'))
        print "starting service", service
        # hot reload of supervisord
        subprocess.check_call(['sudo','supervisorctl','update'])


if __name__ == '__main__':

    p =  "Feb 11 14:55:21 science dhcpd: DHCPOFFER on 10.4.10.119 to 88:30:8a:1a:14:3e (thermostat-1A-14-3E) via eth1"
    import re
    m = re.match(".*DHCPOFFER on ((\d{1,3}\.){3}\d{1,3}) to ((\w{2}:){5}\w{2}) \((.*)\) via (.*)\W*$", p)
    print m
    print m.groups()
