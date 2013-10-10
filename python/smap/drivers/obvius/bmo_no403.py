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

import sys

import re
import csv
import urllib
import datetime, time
import traceback
import urlparse
import base64
import StringIO

import sensordb
import obvius

from twisted.internet import reactor, threads, task
from twisted.internet.defer import DeferredSemaphore, Deferred
from twisted.web.client import Agent, HTTPConnectionPool
from twisted.python import util, log
from twisted.web.http_headers import Headers

from smap import core
from smap.util import periodicSequentialCall, BufferProtocol
import smap.driver
import smap.contrib.dtutil as dtutil

TIMEFMT = "%Y-%m-%d %H:%M:%S"

# make a connection pool
try:
    connection_pool
except NameError:
    connection_pool = HTTPConnectionPool(reactor, persistent=True)
    connection_pool.maxPersistentPerHost = 3


def make_field_idxs(type, header, location=None):
    paths = [None]
    map_ = sensordb.get_map(type, header=header, location=location)
    for t in header[1:]:
        paths.append(None)
        for channel in map_['sensors'] + map_['meters']:
            if t.strip().startswith(channel[0]):
                paths[-1] = (channel[2], channel[3])
                break
    ddups = {}
    for elt in paths:
        if elt:
            name = '-'.join(elt)
            ddups[name] = ddups.get(name, 0) + 1

    for k, v in ddups.iteritems():
        if v > 1:
            print "WARNING:", v, "matching channels for", k
            print header
            print paths
            print ddups
    return paths, map_

class BMOLoader(smap.driver.SmapDriver):
    def setup(self, opts):
        self.url = opts['Url']
        self.meter_type = opts['Metadata/Instrument/Model']
        self.location = opts.get('Metadata/Location/Building', None)
        self.rate = int(opts.get('Rate', 3600))
        self.running = False
        self.agent = Agent(reactor, pool=connection_pool)

#         if not sensordb.get_map(self.meter_type, ):
#             raise SmapLoadError(self.meter_type + " is not a known obvius meter type")
        self.push_hist = dtutil.now() - datetime.timedelta(hours=1)

        self.added = False
        self.set_metadata('/', {
                'Extra/Driver' : 'smap.drivers.obvius.bmo.BMOLoader' })
        self.auth = opts["Auth"]

        # print self.url, self.rate

    def start(self):
        # periodicSequentialCall(self.update).start(self.rate)
        task.LoopingCall(self.update).start(self.rate)

    def done(self, result):
        self.running = False

    def update(self, startdt=None, enddt=None):
        if self.running:
            return
        self.startdt, self.enddt = startdt, enddt
        self.running = True

        # in the processing chain, we first open the page
        d = self.open_page()

        # then read the first result set
        d.addCallback(lambda _: self.process)

        # and add it to the outgoing data.  this will chain additional
        # processes and adds as necessary
        d.addCallback(self.add)

        # finally release the semaphore (even if we got an error)
        d.addCallback(self.done)
        # and consume the error 
        d.addErrback(self.done)
        return d
        
    def open_page(self):
        if not self.startdt:
            self.startdt = self.push_hist
        if not self.enddt:
            self.enddt = dtutil.now()

        start, end = urllib.quote(dtutil.strftime_tz(self.startdt, TIMEFMT)), \
            urllib.quote(dtutil.strftime_tz(self.enddt, TIMEFMT))

        url = self.url % (start, end)
        url += "&mnuStartMonth=%i&mnuStartDay=%i&mnuStartYear=%i" % \
            (self.startdt.month,
             self.startdt.day,
             self.startdt.year)
        url += "&mnuStartTime=%i%%3A%i" % (self.startdt.hour, 
                                           self.startdt.minute)
        url += "&mnuEndMonth=%i&mnuEndDay=%i&mnuEndYear=%i" % \
            (self.enddt.month,
             self.enddt.day,
             self.enddt.year)
        url += "&mnuEndTime=%i%%3A%i" % (self.enddt.hour, self.enddt.minute)
        log.msg("loading " + url)

        # send the auth preemptively to avoid the 403-redirect cycle...
        auth = "Basic " + base64.encodestring(":".join(self.auth))[:-1]
        d = self.agent.request("GET", url,
                               Headers({"Authorization": [auth]}))
        d.addCallback(self.get_response)
        return d

    def get_response(self, response):
        # buffer the response as a string
        done = Deferred()
        response.deliverBody(BufferProtocol(done))
        done.addCallback(self.process)
        return done

    def process(self, body):
        reader = csv.reader(StringIO.StringIO(body), dialect='excel-tab')
        header = reader.next()
        if len(header) == 0:
            print "Warning: no data from", self.url
            raise core.SmapException("no data!")
        try:
            self.field_map, self.map = make_field_idxs(self.meter_type, header, 
                                                       location=self.location)
        except:
            traceback.print_exc()

        if not self.added:
            self.added = True
            for channel in self.map['sensors'] + self.map['meters']:
                try:
                    self.add_timeseries('/%s/%s' % channel[2:4], channel[4], data_type='double')
                    self.set_metadata('/%s/%s' % channel[2:4], {
                            'Extra/ChannelName' : re.sub('\(.*\)', '', channel[0]).strip(),
                            })
                    
                except:
                    traceback.print_exc()

        # add all the values
        for r in reader:
            ts = dtutil.strptime_tz(r[0], TIMEFMT, tzstr='UTC')
            if ts > self.push_hist:
                self.push_hist = ts
            ts = dtutil.dt2ts(ts)

            for descr, val in zip(self.field_map, r):
                if descr == None: continue
                try:
                    self._add('/' + '/'.join(descr), ts, float(val))
                except ValueError:
                    pass
