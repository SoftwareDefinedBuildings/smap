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


Driver using the OPC Labs QuickOPC COM component to communicate with
an OPC server.  Installing this component requires a few steps to
install the appropriate binaries and dlls.  These components are
packaged in smap/win32/bin.

First install the MSVCC redistributable component and OPC Core
Components for your architecture.  Then register the QuickOPC
components for using regsvr32:

> regsvr32 /RegService easyopcl.exe
> regsvr32 easyopci.dll
> regsvr32 easyopcm.dll
> regsvr32 easyopct.dll

For more information, see the "Application Deployment" section of the
QuickOPC Concepts documentation.

@author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
"""

import operator
import re
import subprocess
from twisted.internet import task, protocol, reactor, defer, threads
from twisted.python import log
import string
import random
import time

import win32com.client
import win32api
import win32event
import pythoncom

from smap.driver import SmapDriver
from smap.util import str_path
from smap.contrib import dtutil

NEWLINE = '\r\n'

PROPERTIES = [
    (1, "Item Canonical DataType", "Metdata/Extra/OpcDataType"),
    (100, "EU Units", "Properties/UnitofMeasure"),
    (101, "Item Description", "Description"),
    (108, "Item Timezone", "Extra/OpcTimeZone"),
    ]

OPC_DRIVERS = {}

class OpcEvents(object):
    def OnMultipleItemsChanged(self, sender, args):
        for v in args.ArgsArray:
            driver = OPC_DRIVERS[v.State]
            if v.Exception:
                continue
            print v.ItemDescriptor.ItemId,
            print v.Vtq.Timestamp, v.Vtq.Value
            ts = dtutil.strptime_tz(str(v.Vtq.Timestamp),
                                    "%m/%d/%y %H:%M:%S",
                                    tzstr=driver.opc_timezone)
            path = driver.make_path(v.ItemDescriptor.ItemId)
            try:
                driver._add(driver.make_path(v.ItemDescriptor.ItemId),
                            int(dtutil.dt2ts(ts)),
                            v.Vtq.Value)
            except Exception, e:
                log.err("Error adding data: " + str(e))

class Driver(SmapDriver):
    def setup(self, opts):
        self.opc_name = opts.get('OpcName')
        self.opc_host = opts.get('OpcHost', '127.0.0.1')
        self.opc_timezone = opts.get("OpcTimezone", "UTC")
        self.use_opc_timestamps = bool(opts.get("UseOpcTimestamps", "True").strip().lower())        
        self.rate = float(opts.get("Rate", 1))
        
        if opts.get('OpcPointFile', None):
            with open(opts.get('OpcPointFile'), 'r') as fp:
                self.points = self.parse_pointfile(fp)
        print self.points.keys()

        while True:
            me = ''.join(random.sample(string.letters, 12))
            if me in OPC_DRIVERS: continue
            else:
                OPC_DRIVERS[me] = self
                self.me = me
                break
        print "driver set up"

    def start(self):
        # this should initialize the reactor thread...
        pythoncom.CoInitialize()
        print "starting driver"
        d = threads.deferToThread(self.read_properties)
        d.addCallback(self.add_points)
        d.addCallback(self.subscribe)

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
        pythoncom.CoInitialize()
        
        client = win32com.client.Dispatch("OPCLabs.EasyDAClient.5.1")
        rv = dict((k, dict()) for k in self.points.iterkeys())
        points = self.points.keys()
        for opc_id, opc_name, smap_name in PROPERTIES:
            print self.opc_host, self.opc_name, opc_id
            for i in xrange(0, len(points), 10):
                print "reading", opc_name, i
                vals = client.GetMultiplePropertyValues(self.opc_host,
                                                        self.opc_name,
                                                        points[i:i+10],
                                                        opc_id)
                for point_name, result in zip(self.points, vals):
                    if result.Exception:
                        print "Error reading property", opc_name, "for", point_name
                        continue
                    rv[point_name][smap_name] = str(result.Value)
        # client should get cleaned up when it's garbage collected...
        return rv

    def add_points(self, metadata):
        """Create timeseries for all of the OPC points we're going to subscribe to"""
        for point, meta in metadata.iteritems():
            path = self.make_path(point)
            print "adding timeseries", path
            self.add_timeseries(path,
                                meta.get("Properties/UnitofMeasure", "Unknown"),
                                data_type="double")
            print meta
            self.set_metadata(path, dict(((k, v) for k, v in meta.iteritems()
                                          if k.startswith("Metadata"))))
            self.set_metadata(path, self.points[point])
                              
    def subscribe(self, args):
        pythoncom.CoInitialize()
        self.client = win32com.client.DispatchWithEvents("OPCLabs.EasyDAClient.5.1",
                                                         OpcEvents)
        self.client.SubscribeMultipleItems(self.opc_host,
                                           self.opc_name,
                                           self.points.keys(),
                                           int(self.rate * 1000),
                                           self.me)
        reactor.callLater(0.10, self.com_poll)

    def com_poll(self):
        # check every 100ms for new events
        reactor.callLater(0.10, self.com_poll)
        pythoncom.CoInitialize()
        rc = win32event.MsgWaitForMultipleObjects((win32event.CreateEvent(None, 0, 0, None),),
                                                0,
                                                0,
                                                win32event.QS_ALLEVENTS)
        if rc == win32event.WAIT_OBJECT_0:
            reactor.stop()
        pythoncom.PumpWaitingMessages()

