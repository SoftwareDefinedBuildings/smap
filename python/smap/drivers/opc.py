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
from twisted.internet import task
from twisted.python import log

from smap.driver import SmapDriver
from smap.util import periodicSequentialCall, str_path
from smap.contrib import dtutil

import OpenOPC

# properties not to add as metadata
PROP_FILTER_LIST = [u"Item Timestamp",
                    u"Item Value"]
def exclude(key):
    for exclude in PROP_FILTER_LIST:
       if key.find(exclude) >= 0: return True
    return False

class Driver(SmapDriver):
    def setup(self, opts):
        self.opc_name = opts.get('OpcName')
        self.opc_host = opts.get('OpcHost', '127.0.0.1')
        self.unit_tag = opts.get('OpcUnitProperty', 'Engineering Units')
        self.points = {opts.get('OpcPoint', '*'): {}}
        self.opc_timefmt = opts.get("OpcTimeFormat", "%m/%d/%y %H:%M:%S")
        self.opc_timezone = opts.get("OpcTimezone", "Local")
        
        self.rate = int(opts.get("Rate", 30))
        if opts.get('OpcPointFile', None):
            with open(opts.get('OpcPointFile'), 'r') as fp:
                self.points = self.parse_pointfile(fp)
        print self.points.keys()

    def start(self):
        self.connect()
        self.updater = task.LoopingCall(self.update).start(self.rate)

    def stop(self):
        self.updater.stop()
        self.opc.close()

    def make_path(self, point):
        name = point.split('.')
        name = '/' + '/'.join(map(str_path, name[:-1]))
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
            
    def connect(self):
        print "attempting OPC connection to", self.opc_name
        self.opc = OpenOPC.client()
        self.opc.connect(self.opc_name, self.opc_host)
        props = self.opc.properties(self.points.keys())
        print "loaded", len(props), "properties"
        points = {}
        for point, pid, key, val in props:
            name = self.make_path(point)
            if not name in points:
                points[name] = self.points[point]
            if not exclude(key):
                points[name]['OpcDA/' + key] = str(val)

        # try to make some sense out of the metadata
        for name, meta in points.iteritems():
            unit = str(meta.get('OpcDA/' + self.unit_tag, 'None'))
            dtype = meta.get('OpcDA/Item Canonical DataType', None)
            if not dtype:
                print "no datatype tag in", name
                continue
            if dtype.startswith('VT_R'):
                dtype = 'double'
            elif dtype.startswith('VT_U') or dtype.startswith('VT_I'):
                dtype = 'long'
            else:
                print "skipping", name, "since cannot find data type"
                continue
            if not self.get_timeseries(name):
                self.add_timeseries(name, unit, data_type=dtype)
                self.set_metadata(name, points[name])
        vals = self.opc.read(self.points.keys(), group="smap-points-group")

    def _update(self):
        vals = self.opc.read(group="smap-points-group")
        for point, value, quality, time in vals:
            # parse the timestamp in the timezone of the server
            ts = dtutil.strptime_tz(time, self.opc_timefmt, self.opc_timezone)
            ts = dtutil.dt2ts(ts)
            self._add(self.make_path(point), ts, value)

    def update(self):
        try:
            if not hasattr(self, 'opc'):
                self.connect()
            else:
                self._update()
        except:
            log.err()

            # try to clean up and reconnect on an error
            try:
                self.opc.remove(self.opc.groups())
            except:
                pass
            
            try:
                self.opc.close()
            except:
                pass
            del self.opc
