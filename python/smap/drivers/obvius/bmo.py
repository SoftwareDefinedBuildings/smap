
import sys

import csv
import urllib
import datetime, time

import sensordb
import auth
import obvius

from twisted.internet import reactor, threads

import smap.driver
from smap.util import periodicSequentialCall
import smap.iface.http.httputils as httputils
import smap.contrib.dtutil as dtutil

TIMEFMT = "%Y-%m-%d %H:%M:%S"

def make_field_idxs(type, header):
    paths = [None]
    for t in header[1:]:
        map_ = sensordb.get_map(type)
        paths.append(None)
        for channel in map_['sensors'] + map_['meters']:
            if t.strip().startswith(channel[0]):
                paths[-1] = (channel[2], channel[3])
    ddups = {}
    for elt in paths:
        if elt:
            name = '-'.join(elt)
            ddups[name] = ddups.get(name, 0) + 1
    for k, v in ddups.iteritems():
        if v > 1:
            print "WARNING:", v, "matching channels for", k
    return paths

class BMOLoader(smap.driver.SmapDriver):
    def setup(self, opts):
        self.url = opts['Url']
        self.meter_type = opts['Metadata/Instrument/Model']
        self.rate = int(opts.get('Rate', 3600))
        if not sensordb.get_map(self.meter_type):
            raise SmapLoadError(self.meter_type + " is not a known obvius meter type")
        self.push_hist = dtutil.now() - datetime.timedelta(days=1)

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
        periodicSequentialCall(self.update).start(self.rate)

    def update(self):
        print "Starting update cycle"
        enddt = dtutil.now()
        start, end = urllib.quote(dtutil.strftime_tz(self.push_hist, TIMEFMT)), \
            urllib.quote(dtutil.strftime_tz(enddt, TIMEFMT))

        url = self.url % (start, end)
        url += "&mnuStartMonth=%i&mnuStartDay=%i&mnuStartYear=%i" % \
            (self.push_hist.month,
             self.push_hist.day,
             self.push_hist.year)
        url += "&mnuStartTime=%i%%3A%i" % (self.push_hist.hour, 
                                           self.push_hist.minute)
        url += "&mnuEndMonth=%i&mnuEndDay=%i&mnuEndYear=%i" % \
            (enddt.month,
             enddt.day,
             enddt.year)
        url += "&mnuEndTime=%i%%3A%i" % (enddt.hour, enddt.minute)

        self.fp = httputils.load_http(url, as_fp=True, auth=auth.BMOAUTH)
        if not self.fp:
            print "WARNING : timeout"
            return
        self.reader = csv.reader(self.fp, dialect='excel-tab')
        header = self.reader.next()
        if len(header) == 0:
            print "Warning: no data from", self.url
            return
        self.field_map = make_field_idxs(self.meter_type, header)
        # print '\n'.join(map(str, (zip(header, field_map))))
        threads.deferToThread(self.process)

    def process(self):
        if self.reader == None: return
        readcnt = 0
        self.data = []
        for r in self.reader:
            ts = dtutil.strptime_tz(r[0], TIMEFMT, tzstr='UTC')
            if ts > self.push_hist:
                self.push_hist = ts
            ts = dtutil.dt2ts(ts)

            self.data.append((ts, zip(self.field_map, r)))

            readcnt += 1
            if readcnt > 10:
                reactor.callFromThread(self.add)
                return

        self.fp.close()
        self.reader = None
        reactor.callFromThread(self.add)

    def add(self):
        for ts, rec in self.data:
            for descr, val in rec:
                if descr == None: continue
                try:
                    self._add('/' + '/'.join(descr), ts, float(val))
                except ValueError:
                    pass
        self.data = []
        threads.deferToThread(self.process)



