"""
Copyright (c) 2011, 2012, Regents of the University of California
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

import operator
import re
import subprocess
from twisted.internet import task, protocol, reactor, defer
from twisted.python import log

from smap.driver import SmapDriver
from smap.util import periodicSequentialCall, str_path
from smap.contrib import dtutil

NEWLINE = '\r\n'

# properties not to add as metadata
PROP_FILTER_LIST = [u"Item Timestamp",
                    u"Item Value"]
def exclude(key):
    for exclude in PROP_FILTER_LIST:
       if key.find(exclude) >= 0: return True
    return False

class OpcProcessProtocol(protocol.ProcessProtocol):
    def __init__(self, opc_driver,
                 deliver, done,
                 forever=False):
        self.opc_driver = opc_driver
        self.deliver = deliver
        self.done = done
        self.data = ''
        self.forever = forever
        
    def connectionMade(self):
        for point in self.opc_driver.points.iterkeys():
            self.transport.write(point + NEWLINE)
        self.transport.closeStdin()

    def outReceived(self, data):
        self.data += data
        # print self.data
        while self.data.find(NEWLINE) > 0:
            idx = self.data.index(NEWLINE)
            vals = self.data[:idx].split(',')
            if len(vals) == 4:
                self.deliver(vals)
            else:
                print "bad data", self.data[:idx]
                # self.transport.signalProcess('KILL')
            self.data = self.data[idx+len(NEWLINE):]

    def processExited(self, reason):
        # print "OPC process exited:", reason.value.exitCode
        self.done()

    def processEnded(self, reason):
        #print "OPC process ended:", reason.value.exitCode
        pass

class Driver(SmapDriver):
    def setup(self, opts):
        self.opc_name = opts.get('OpcName')
        self.opc_host = opts.get('OpcHost', '127.0.0.1')
        self.unit_tag = opts.get('OpcUnitProperty', 'Engineering Units')
        self.points = {opts.get('OpcPoint', '*'): {}}
        self.opc_timefmt = opts.get("OpcTimeFormat", "%m/%d/%y %H:%M:%S")
        self.opc_timezone = opts.get("OpcTimezone", "UTC")
        self.opc_datatype = opts.get("OpcDatatype", 'Item Canonical Data Type')
        self.opc_group_size = opts.get("OpcGroupSize", 100)
        self.use_opc_timestamps = opts.get("UseOpcTimestamps", "True").strip().lower()
        self.opc_cmd = opts.get("OpcCommand", r"c:\OpenOPC\bin\opc.exe")
        
        self.rate = float(opts.get("Rate", 30))
        if opts.get('OpcPointFile', None):
            with open(opts.get('OpcPointFile'), 'r') as fp:
                self.points = self.parse_pointfile(fp)
        print self.points.keys()

    def start(self):
        d = self.read_properties()
        d.addCallback(self.add_properties)
        d.addCallback(self.start_updater)

    def make_path(self, point):
        point = point.replace('/', '_')
        name = point.split('.')
        name = '/' + '/'.join(map(str_path, name))
        return name

    def parse_pointfile(self, fp):
        pointdfns = {}
        cur_tag = None
        while True:
            line = fp.readline()
            if not line: break
            line = re.sub("#(.*)$", "", line.rstrip())
            if not re.match("^[ ]+", line):
                pointdfns[line] = {}
                cur_tag = line
            elif cur_tag:
                pieces = line.lstrip().split(" ")
                pointdfns[cur_tag][pieces[0]] = ' '.join(pieces[1:])
        return pointdfns

    def read_properties(self):
        args = [self.opc_cmd,
                '-s', self.opc_name,
                '-h', self.opc_host,
                '-o', 'csv',
                '-g', str(self.opc_group_size),
                '-p', '-']
        print "reading properties"
        properties = []
        d = defer.Deferred()
        def append_prop(dat):
            properties.append(dat)

        def _add_props():
            d.callback(properties)

        rec = OpcProcessProtocol(self, append_prop, _add_props)
        reactor.spawnProcess(rec, self.opc_cmd, args, {})
        return d

    def start_updater(self, *args):
        args = [self.opc_cmd,
                '-s', self.opc_name,
                '-h', self.opc_host,
                '-o', 'csv',
                '-r', # read
                '-g', str(self.opc_group_size), #  tags per transaction
                '-L', str(self.rate),
                '-']
        print "starting updater", args

        rec = OpcProcessProtocol(self, self._update, self._done)
        reactor.spawnProcess(rec, self.opc_cmd, args, {})
        #reactor.addSystemEventTrigger('after', 'shutdown',
        #                              lambda: rec.transport.signalProcess('KILL'))
    def add_properties(self, props):
        #print "attempting OPC connection to", self.opc_name
        #props = self.opc.properties(self.points.keys())
        print "loaded", len(props), "properties"
        points = {}
        for point, pid, key, val in props:
            name = self.make_path(point)
            print name
            if not point in self.points:
                continue
            if not name in points:
                points[name] = self.points[point]
            if not exclude(key):
                points[name]['OpcDA/' + key] = str(val)

        # try to make some sense out of the metadata
        for name, meta in points.iteritems():
            unit = str(meta.get('OpcDA/' + self.unit_tag, 'None'))
            dtype = meta.get('OpcDA/' + self.opc_datatype, None)
            if not dtype:
                log.err("no datatype tag in " + name)
                dtype = 'VT_R'
            
            if dtype.startswith('VT_R'):
                dtype = 'double'
            elif dtype.startswith('VT_U') or dtype.startswith('VT_I'):
                dtype = 'long'
            else:
                print "skipping", name, "since cannot find data type"
                continue
            if not self.get_timeseries(name):
                self.add_timeseries(name, unit, data_type=dtype)
                self.set_metadata(name, meta)

    def _update(self, val):
        print "update using", val
        try:
            point, value, quality, time = val
            if quality != 'Good':
                log.msg("bad quality on point " + point + ": " + quality)
                return

            # parse the timestamp in the timezone of the server
            if self.use_opc_timestamps == 'true':
                ts = dtutil.strptime_tz(time,
                                        self.opc_timefmt,
                                        self.opc_timezone)
                ts = dtutil.dt2ts(ts)
            else:
                ts = dtutil.dt2ts(dtutil.now())

            path = self.make_path(point)
            series = self.get_timeseries(path)
            if series:
                if series['Properties']['ReadingType'] == 'double':
                    series._add(ts, float(value))
                else:
                    series._add(ts, int(value))
        except:
            log.err()

    def _done(self):
        print "done; stopping reactor.  received exception?"
        reactor.stop()
