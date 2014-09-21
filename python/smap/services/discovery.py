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
@author Gabe Fierro <gt.fierro@berkeley.edu>
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
from history import Historian

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
        self.config_repo = opts.get("config_repo", '.')
        self.db = {}
        self._driverport = 1234
        self._nmap_path = opts.get('nmap_path','/usr/bin/nmap')
        self._scripts_path = opts.get('scripts_path','scripts')
        self.historian = Historian('/var/smap','discovery')
        self.discovery_sources = [
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
        if dev.mac in self.historian.config:
            # if we've seen it before, check to see if we have the same IP for it as before
            # if we have the same IP, we skip it
            # if we have a new IP, remove the old ini and conf files, add the new one, and run 'supervisor update',
            # which will stop the old process automatically
            if self.historian.config[dev.mac]['ip'] == dev.ip:
                return
            else:
                os.remove(self.historian[dev.mac]['conf'])
                os.remove(self.historian[dev.mac]['ini'])
        else:
            self.historian.config[dev.mac] = dev.to_json()
        if not dev.last_discovery and not dev.scan_pending:
            dev.scan_pending = True
            print "Scheduling device scan", dev
            reactor.callLater(DETECT_SCAN_WAIT, self.scan_device, dev)

    def error(self, *args):
        print 'Error:',args[1].ip, args[1].mac
        print args

    def scan_device(self, dev):
        # if dev.ip != '10.4.10.100': return
        d = defer.Deferred()
        pp = XmlProcessProtocol(d)
        print "Starting scan of", dev.ip
        reactor.spawnProcess(pp, self._nmap_path, ['nmap', "--script={0}".format(self._scripts_path), '-oX', '-', dev.ip])
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
        print services
        configs = map(self.update_config, services)
        map(self.start_service, services)

    def update_config(self, service):
        strname = service.script + "-" + service.dev.ip.replace('.','_')
        path = os.path.join(self.config_repo, strname + '.ini')
        print self.historian.config
        self.historian.config[service.dev.mac]['ini'] = path
        print "\tupdating config", path
        with open(path, 'w') as fp:
            print >>fp, """

[report 0]
ReportDeliveryLocation = mongo://localhost:3001

[report 1]
ReportDeliveryLocation = http://localhost:8079/add/lVzBMDpnkXApJmpjUDSvm4ceGfpbrLLSd9cq

[report 2]
ReportDeliveryLocation = http://archiver.cal-sdb.org:9000/data/legacyadd/likeaboss

[/]
uuid = %(uuid)s
Metadata/SourceName = %(strname)s

[server]
datadir = /tmp

[/%(strname)s]
uuid = %(uuid)s
""" % {'strname': strname, 'uuid': str(self.uuid(service.dev.key()))}
            for k, v in service.conf.iteritems():
                print >>fp, k.replace("__", "/"), "=", v
        return path

    def start_service(self, service):
        strname = service.script + "-" + service.dev.ip.replace('.','_')
        c = ConfigParser.RawConfigParser()
        programname = 'program:{0}'.format(strname)
        # remove old config section
        c.remove_section(programname)
        # add new section
        c.add_section(programname)
        # use custom port and custom pidfile
        c.set(programname,'command','twistd --pidfile=/var/run/smap/{strname}.pid -n smap -p {port} {config_repo}/{strname}.ini'.format(config_repo=self.config_repo, strname=strname, port=self.driverport))
        c.set(programname,'priority',2)
        c.set(programname,'autorestart',True)
        c.set(programname,'user','smap')
        c.set(programname,'stdout_logfile','/var/log/{0}.stdout.log'.format(strname))
        c.set(programname,'stdout_logfile_maxbytes','50MB')
        c.set(programname,'stdout_logfile_backups',5)
        c.set(programname,'stderr_logfile','/var/log/{0}.stderr.log'.format(strname))
        c.set(programname,'stderr_logfile_maxbytes','50MB')
        c.set(programname,'stderr_logfile_backups',5)
        filename = '/etc/supervisor/conf.d/{0}.conf'.format(strname)
        c.write(open(filename,'w+'))
        self.historian.config[service.dev.mac]['conf'] = filename
        self.historian.save()
        print "starting service", service
        # hot reload of supervisord
        subprocess.check_call(['sudo','supervisorctl','update','-c','/etc/supervisor/supervisord.conf'])


if __name__ == '__main__':

    p =  "Feb 11 14:55:21 science dhcpd: DHCPOFFER on 10.4.10.119 to 88:30:8a:1a:14:3e (thermostat-1A-14-3E) via eth1"
    import re
    m = re.match(".*DHCPOFFER on ((\d{1,3}\.){3}\d{1,3}) to ((\w{2}:){5}\w{2}) \((.*)\) via (.*)\W*$", p)
    print m
    print m.groups()
