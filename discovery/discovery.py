#! -*- python -*-

import os
import re
import xml.etree.ElementTree as ET

from twisted.internet import reactor, protocol, defer
from twisted.internet.utils import getProcessOutputAndValue

from smap.driver import SmapDriver
from smap.iface import tail

# number of seconds to wait between detecting a device and scanning it.
DETECT_SCAN_WAIT = 1

class PushError(Exception):
    pass

class Device(object):
    def key(self):
        return self.ip + '-' + self.mac

    def __init__(self, ip, mac, name, iface):
        self.ip = ip
        self.mac = mac
        self.name = name
        self.iface = iface

        # the time we last ran discovery
        self.last_discovery = None
        self.scan_pending = False

    def __str__(self):
        return self.ip

class Service(object):
    """Container for something that can be represented as a smap
    service on a device"
    """
    def __init__(self, dev, script, conf):
        self.dev = dev
        self.script = script
        self.conf = conf

    def __str__(self):
        return self.script + " @ " + str(self.dev)

class XmlProcessProtocol(protocol.ProcessProtocol):
    def __init__(self, done):
        self.data = []
        self.done = done
    def outReceived(self, data):
        self.data.append(data)
    def errorReceived(self, data):
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
        self.syslog = opts.get("syslog", "/var/log/syslog")
        self.config_repo = opts.get("config_repo", '/home/stevedh/develop/smap-configs/')
        self.tailer = tail.FollowTail(self.syslog, seekend=False)
        self.tailer.lineReceived = self.syslogLineReceived
        self.db = {}

    def start(self):
        self.tailer.start()

    def stop(self):
        self.tailer.stop()

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

        dev = Device(ip, mac, name, iface)
        self.update_device(dev)

    def update_device(self, dev):
        if dev.key() in self.db:
            # print "Device already discovered:", dev
            dev = self.db[dev.key()]
        else:
            self.db[dev.key()] = dev

        if not dev.last_discovery and not dev.scan_pending:
            dev.scan_pending = True
            print "Schedulding device scan", dev
            reactor.callLater(DETECT_SCAN_WAIT, self.scan_device, dev)

    def scan_device(self, dev):
        # if dev.ip != '10.4.10.100': return
        d = defer.Deferred()
        pp = XmlProcessProtocol(d)
        print "Starting scan of", dev.ip
        reactor.spawnProcess(pp, 'nmap', ['nmap', "--script=scripts", '-oX', '-', dev.ip])
        d.addCallback(self.process_scan_results, dev)
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
                    services.append(Service(dev, script.attrib['id'], conf))
        print len(services), "sMAP service(s) found:"
        if len(services): print "\t" + (" ".join((s.script for s in services)))
        return services
            
    def register_services(self, services):
        configs = map(self.update_config, services)
        for svc, d in zip(services, map(self.push_config, configs)):
            d.addCallback(self.start_service, svc)

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
                raise PushError(stderr)
        d.addCallback(check_commit)
        return d

    def start_service(self, result, svc):
        print "starting service", svc

if __name__ == '__main__':

    p =  "Feb 11 14:55:21 science dhcpd: DHCPOFFER on 10.4.10.119 to 88:30:8a:1a:14:3e (thermostat-1A-14-3E) via eth1"
    import re
    m = re.match(".*DHCPOFFER on ((\d{1,3}\.){3}\d{1,3}) to ((\w{2}:){5}\w{2}) \((.*)\) via (.*)\W*$", p)
    print m
    print m.groups()
