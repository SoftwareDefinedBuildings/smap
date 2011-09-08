
import sys

import csv
import urllib
import datetime, time

import sensordb
import auth
import obvius

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
        self.rate = opts.get('Rate', 3600)
        if not self.meter_type in sensordb.TYPES:
            raise SmapLoadError(self.meter_type + " is not a known obvius meter type")
        self.push_hist = None

        map_ = sensordb.get_map(self.meter_type)
        self.set_metadata('/', {
                'Extra/Driver' : 'smap.drivers.obvius.bmo.BMOLoader' })
        for channel in map_['sensors'] + map_['meters']:
            self.add_timeseries('/%s/%s' % channel[2:4], channel[4], data_type='double')
            self.set_metadata('/%s' % channel[2], {
                    'Extra/Phase' : channel[2]})

        print self.url, self.rate

    def start(self):
        periodicSequentialCall(self.update).start(self.rate)

    def update(self):
        self.push_hist = dtutil.now() - datetime.timedelta(days=1)
        start, end = urllib.quote(dtutil.strftime_tz(self.push_hist, TIMEFMT)), \
            urllib.quote(dtutil.strftime_tz(dtutil.now(), TIMEFMT))
        print start, end

        fp = httputils.load_http(self.url % (start, end),
                                 as_fp=True, auth=auth.BMOAUTH)
        reader = csv.reader(fp, dialect='excel-tab')
        header = reader.next()
        if len(header) == 0:
            print "Warning: no data from", self.url
            return
        field_map = make_field_idxs(self.meter_type, header)
        # print '\n'.join(map(str, (zip(header, field_map))))

        self.data = []
        for r in reader:
            ts = dtutil.strptime_tz(r[0], TIMEFMT, tzstr='UTC')
            if ts > self.push_hist:
                self.push_hist = ts
            print ts
            ts = dtutil.dt2ts(ts)

            for descr, val in zip(field_map, r):
                if descr == None: continue
                try:
                    self.add('/' + '/'.join(descr), ts, float(val))
                except ValueError:
                    pass


