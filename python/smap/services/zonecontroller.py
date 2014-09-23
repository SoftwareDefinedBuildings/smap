"""
@author Gabe Fierro <gt.fierro@berkeley.edu>
"""

from smap.driver import SmapDriver
from smap.actuate import SmapActuator, ContinuousIntegerActuator
from smap.util import periodicSequentialCall, join_path
from smap import loader
from smap.archiver.client import RepublishClient
from functools import partial
import importlib
from uuid import uuid1 as uuid
from configobj import ConfigObj

class ZoneController(SmapDriver):
    def setup(self, opts):
        self.rate = int(opts.get('rate', 1))
        self.synchronous = opts.get('synchronous').lower() == 'true'
        self.archiver_url = opts.get('archiver')
        self.points = {}
        self.repubclients = {}
        self._loop = None
        for k,v in opts.iteritems():
            if k.startswith('subscribe/'):
                point = k.split('/')[-1]
                self.points[point] = None
                self.repubclients[point] = [RepublishClient(self.archiver_url, partial(self.cb, point), restrict=v)]

    def add_callback(self, point, function, where):
        self.repubclients[point].append(RepublishClient(self.archiver_url, partial(function, point), restrict=where))

    def start(self):
        if self.synchronous:
            self._loop = periodicSequentialCall(self._step)
            self._loop.start(self.rate)
        # start subscriptions
        for clientlist in self.repubclients.itervalues():
            for c in clientlist:
                c.connect()

    def stop(self):
        """
        Graceful shutdown for a zone controller
        """
        if self._loop:
            self._loop.stop()
        for point in self.repubclients:
            map(lambda x: x.close(), self.repubclients[point])

    def _step(self):
        self.points = {k: v for k,v in self.points.iteritems() if v is not None}
        self.step()

    def set_name(self, name):
        self.set_metadata('/',{'Metadata/Name': str(name)})
        
    def step(self):
        # publish new setpoints
        print 'stepping'
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

"""
We tell the Decider driver about a standalone ini file (that is, a dormant one and not the one that contains
the Decider ini) and it will have the ability to start drivers from that file

It should probably be the case that when we start a driver, we add the metadata for the Decider to that driver,
this way they can just be drop-in replacements for previous zone controllers


"""
class Decider(SmapDriver):
    def setup(self, opts):
        self.zc_config_file = opts.get('configfile', 'zc.ini')
        self.zc_config = ConfigObj(self.zc_config_file)
        # this is the full path of the zone controller
        self.zc_section = '/' + opts.get('section')
        self.zc_class = self.zc_config[self.zc_section]['type']
        # get all but the class name
        module_path = '.'.join(self.zc_class.split('.')[:-1])
        # get the class name
        klass = self.zc_class.split('.')[-1]
        # import the module containing the class
        module = importlib.import_module(module_path)
        # get the class type from the module
        self.zc = getattr(module, klass)
        # instantiate the driver
        self.d = SmapDriver.get_driver(self._SmapDriver__inst, self.zc_class,self.zc_section, uuid())
        print self.zc_config[self.zc_section]
        self.d.setup(self.zc_config[self.zc_section])

        self.act = self.add_timeseries('/zonecontroller','class',data_type='long')
        self.set_metadata('/zonecontroller', {'Class': self.zc_class})
        self.act.add_actuator(DeciderActuator(decider=self))

    def start(self):
        self.metadata = self.get_timeseries('/zonecontroller')['Metadata']
        

class _baseactuator(SmapActuator):
    def __init__(self, **opts):
        self.decider = opts.get('decider')

class DeciderActuator(_baseactuator, ContinuousIntegerActuator):
    def __init__(self, **opts):
        ContinuousIntegerActuator.__init__(self, [0,1000])
        _baseactuator.__init__(self, **opts)

    def set_state(self, request, state):
        zonecontroller = request.content.read()
        self.decider.d.stop()
        for endpoint in self.decider.d.get_collection('/')['Contents']:
            j = self.decider.zc_section + '/' + endpoint
            if j in self.decider._SmapDriver__inst.OBJS_PATH:
                self.decider._SmapDriver__inst.OBJS_PATH.pop(j)
        self.decider._SmapDriver__inst.OBJS_PATH.pop(self.decider.zc_section)
        self.decider.zc_section = '/'+zonecontroller
        self.decider.d = SmapDriver.get_driver(self.decider._SmapDriver__inst, self.decider.zc_class, '/'+zonecontroller, uuid())
        self.decider.d.setup(self.decider.zc_config['/'+zonecontroller])
        self.decider.d.start()
