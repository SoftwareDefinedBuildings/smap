"""
Default zone controller

Timeseries URI endpoints are declared directly, e.g.
        self.add_timeseries('/temp_heat', 'F', data_type='double')


"""
"""
@author Gabe Fierro <gt.fierro@berkeley.edu>
"""

from smap.driver import SmapDriver
from smap.actuate import SmapActuator
from smap.util import periodicSequentialCall
from smap.archiver.client import RepublishClient
from functools import partial

class ZoneController(SmapDriver):
    def setup(self, opts):
        self.rate = int(opts.get('rate', 1))
        self.synchronous = opts.get('synchronous').lower() == 'true'
        self.archiver_url = opts.get('archiver')
        self.points = {}
        self.repubclients = {}
        for k,v in opts.iteritems():
            if k.startswith('subscribe/'):
                point = k.split('/')[-1]
                self.points[point] = None
                self.repubclients[point] = [RepublishClient(self.archiver_url, partial(self.cb, point), restrict=v)]

        self.add_timeseries('/temp_heat', 'F', data_type='double')
        self.add_timeseries('/temp_cool', 'F', data_type='double')

    def add_callback(self, point, function, where):
        self.repubclients[point].append(RepublishClient(self.archiver_url, partial(function, point), restrict=where))

    def start(self):
        if self.synchronous:
            periodicSequentialCall(self.step).start(self.rate)
        # start subscriptions
        for clientlist in self.repubclients.itervalues():
            for c in clientlist:
                c.connect()

    def step(self):
        # publish new setpoints
        for point, value in self.points.iteritems():
            if not (value is None) and self.get_timeseries('/'+point):
                print 'publishing',point,'=',value
                self.add('/'+point, float(value))

    def cb(self, point, _, data):
        value = data[-1][-1][1]
        print 'Received',point,'=',value
        self.points[point] = value
        if not self.synchronous:
            self.add('/'+point, float(value))


    def sensor_callback(self, point, uuids, data):
        print 'uuids',uuids
        print 'data',data
        avg_temp = sum(map(lambda x: x[-1][1], data)) / float(len(data))
        print 'average temperature', avg_temp
