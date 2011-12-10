
import uuid
import time
from twisted.internet import reactor, task, threads
from zope.interface import implements

from interface import *
import core
import util
import loader
import server

class SmapDriver:
    # this is actually a shim layer which presents a ISmapInstance to
    # drivers
    implements(ISmapInstance)

    @classmethod
    def get_driver(cls, inst, name, attach_point, namespace):
        """Create a managed driver which will manage a driver whose
        implementation is named by "name"
        """
        cmps = name.split('.')
        mod = __import__('.'.join(cmps[:-1]), globals(), locals(), [cmps[-1]]) 
        klass = getattr(mod, cmps[-1])
        driver = klass(inst, attach_point, namespace)
        inst.add_driver(attach_point, driver)
        return driver

    flush = lambda self: self.__inst.reports.flush()
    _flush = lambda self: self.__inst.reports._flush()

    def __init__(self, smap_instance, attach_point, namespace):
        self.__inst = smap_instance
        self.__attach_point = attach_point
        self.namespace = namespace

    def __join_id(self, id):
        if util.is_string(id) and id.startswith('/'):
            return util.norm_path(self.__attach_point + '/' + id)
        else:
            return id

    # override
    def setup(self, opts={}):
        pass

    # override
    def start(self):
        pass

    # ISmapInstance implementation

    # drivers get a pass-through version of the SmapInstance which
    # knows where they are attached in the tree.  Drivers may, for the
    # most part, assume that they have the instance to themselves.
    # However, the main exception to this is that their names are
    # still in a global namespace.  Therefore they should either
    # generate their own uuids for their streams based on the uuid in
    # their root collection (inst.get_collection('/')['uuid'])
    def lookup(self, id, **kwargs):
        return self.__inst.lookup(self.__join_id(id), **kwargs)
    def get_timeseries(self, id):
        return self.__inst.get_timeseries(self.__join_id(id))
    def get_collection(self, id):
        return self.__inst.get_collection(self.__join_id(id))
    def add_timeseries(self, path, *args, **kwargs):
        kwargs['namespace'] = self.namespace
        if len(args) <= 1:
            key = path
        elif len(args) == 2:
            key = args[0]
            args = args[1:]
        return self.__inst.add_timeseries(self.__join_id(path), key, *args, **kwargs)
    def add_actuator(self, path, unit, klass, **kwargs):
        return self.add_timeseries(path, unit, klass=klass, **kwawrgs)
    def add_collection(self, path, *args):
        self.__inst.add_collection(self.__join_id(path), *args)
    def set_metadata(self, id, *metadata):
        return self.__inst.set_metadata(self.__join_id(id), *metadata)
    def add(self, id, *args):
        return self.__inst.add(self.__join_id(id), *args)
    def _add(self, id, *args):
        return self.__inst._add(self.__join_id(id), *args)

class BaseDriver(SmapDriver):
    def setup(self, opts={}):
        self.t = self.add_timeseries('/sensor0', 'mytimeseries', 'SDH')
        self.set_metadata('/sensor0', { 
            'Instrument/ModelName' : 'ExampleInstrument',
            'Extra/ModbusAddr' : opts.get('ModbusAddr', '')
            })
        self.counter = int(opts.get('StartVal', 0))

    def start(self):
        self.counter = 0
        util.periodicSequentialCall(self.read).start(1)

    def read(self):
        # print "Add", self.counter
        self.t.add(self.counter)
        self.counter += 1
        # print self.counter


if __name__ == '__main__':
    # inst = loader.load('default.ini', autoflush=False)
    # d = SmapDriverManager.get_driver('driver.BaseDriver', '/newsensor')
    # d.setup(inst)
    import uuid
    inst = core.SmapInstance(uuid.uuid1())
    bd = SmapDriver.get_driver(inst, 'driver.BaseDriver', '/newsensor', None)
    bd.setup()

    server.run(inst)
