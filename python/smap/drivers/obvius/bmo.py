
import sys

import csv
import urllib
import datetime, time

import sensordb
import auth
import obvius

from twisted.internet import reactor, threads, task
from twisted.internet.defer import DeferredSemaphore, Deferred

from smap import core
from smap.util import periodicSequentialCall
import smap.driver
import smap.iface.http.httputils as httputils
import smap.contrib.dtutil as dtutil

TIMEFMT = "%Y-%m-%d %H:%M:%S"

# to prevent killing their db, we make all driver instances acquire
# this semaphore before trying to download data
active_reads = DeferredSemaphore(3)

def make_field_idxs(type, header):
    paths = [None]
    for t in header[1:]:
        map_ = sensordb.get_map(type)
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
    return paths

class BMOLoader(smap.driver.SmapDriver):
    def setup(self, opts):
        self.url = opts['Url']
        self.meter_type = opts['Metadata/Instrument/Model']
        self.rate = int(opts.get('Rate', 3600))
        self.running = False

        if not sensordb.get_map(self.meter_type):
            raise SmapLoadError(self.meter_type + " is not a known obvius meter type")
        self.push_hist = dtutil.now() - datetime.timedelta(hours=1)

        map_ = sensordb.get_map(self.meter_type)
        self.set_metadata('/', {
                'Extra/Driver' : 'smap.drivers.obvius.bmo.BMOLoader' })
        for channel in map_['sensors'] + map_['meters']:
            self.add_timeseries('/%s/%s' % channel[2:4], channel[4], data_type='double')
            self.set_metadata('/%s' % channel[2], {
                    'Extra/Phase' : channel[2],
                    'Extra/ChannelName' : channel[0],
                    })

        print self.url, self.rate

    def start(self):
        # periodicSequentialCall(self.update).start(self.rate)
        task.LoopingCall(self.update).start(self.rate)

    def done(self, result):
        self.running = False
        active_reads.release()

    def update(self, startdt=None, enddt=None):
        if self.running:
            return
        self.startdt, self.enddt = startdt, enddt

        self.running = True
        d = active_reads.acquire()
        # in the processing chain, we first open the page
        d.addCallback(lambda _: threads.deferToThread(self.open_page))

        # then read the first result set
        d.addCallback(lambda _: threads.deferToThread(self.process))

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
        print start, end

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
        print "loading", url

        self.fp = httputils.load_http(url, as_fp=True, auth=auth.BMOAUTH)
        if not self.fp:
            raise core.SmapException("timeout!")
        self.reader = csv.reader(self.fp, dialect='excel-tab')
        header = self.reader.next()
        if len(header) == 0:
            print "Warning: no data from", self.url
            raise core.SmapException("no data!")
        self.field_map = make_field_idxs(self.meter_type, header)
        # print '\n'.join(map(str, (zip(header, field_map))))

    def process(self):
        readcnt = 0
        data = []

        if self.reader == None: 
            return data

        try:
            for r in self.reader:
                ts = dtutil.strptime_tz(r[0], TIMEFMT, tzstr='UTC')
                if ts > self.push_hist:
                    self.push_hist = ts
                ts = dtutil.dt2ts(ts)

                data.append((ts, zip(self.field_map, r)))

                readcnt += 1
                if readcnt > 100:
                    return data
        except Exception, e:
            self.fp.close()
            self.reader = None
            raise e

        self.fp.close()
        self.reader = None
        return data

    def add(self, data):
        if len(data) == 0:
            return "DONE"

        for ts, rec in data:
            for descr, val in rec:
                if descr == None: continue
                try:
                    self._add('/' + '/'.join(descr), ts, float(val))
                except ValueError:
                    pass
        self.data = []
        d = threads.deferToThread(self.process)
        d.addCallback(self.add)
        return d


