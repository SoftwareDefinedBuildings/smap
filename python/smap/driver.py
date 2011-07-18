
import uuid
import time
from twisted.internet import reactor, task, threads
from zope.interface import implements

from interface import *
import core
import util
import loader
import server

class SmapDriverManager:
    # this is actually a shim layer which presents a ISmapInstance to
    # drivers and a ISmapDriver to instances.
    implements(ISmapInstance)
    # implements(ISmapDriver)

    @classmethod
    def get_driver(cls, name, attach_point, namespace):
        """Create a managed driver which will manage a driver whose
        implementation is named by "name"
        """
        cmps = name.split('.')
        mod = __import__('.'.join(cmps[:-1]), globals(), locals(), [cmps[-1]]) 
        klass = getattr(mod, cmps[-1])
        driver = SmapDriverManager(klass, attach_point, namespace)
#        print driver
#         if not ISmapDriver.providedBy(driver):
#             raise core.SmapException('The class %s does not provide ISmapDriver' % name)
        return driver
    flush = lambda self: self.smap_instance.reports.flush()
    _flush = lambda self: self.smap_instance.reports._flush()

    def __init__(self, driver_class, attach_point, namespace):
        self.driver_class = driver_class
        self.attach_point = attach_point
        self.driver = self.driver_class()
        self.namespace = namespace

    def join_id(self, id):
        if util.is_string(id) and id.startswith('/'):
            return util.norm_path(self.attach_point + '/' + id)
        else:
            return id

    def setup(self, inst, opts={}):
        self.smap_instance = inst
        col = self.smap_instance.get_collection(self.attach_point)
        self.driver.setup(self, opts=opts)

    def start(self):
        return self.driver.start()

    # ISmapInstance implementation

    # drivers get a pass-through version of the SmapInstance which
    # knows where they are attached in the tree.  Drivers may, for the
    # most part, assume that they have the instance to themselves.
    # However, the main exception to this is that their names are
    # still in a global namespace.  Therefore they should either
    # generate their own uuids for their streams based on the uuid in
    # their root collection (inst.get_collection('/')['uuid'])
    def lookup(self, id, **kwargs):
        return self.smap_instance.lookup(self.join_id(id), **kwargs)
    def get_timeseries(self, id):
        return self.smap_instance.get_timeseries(self.join_id(id))
    def get_collection(self, id):
        return self.smap_instance.get_collection(self.join_id(id))
    def add_timeseries(self, path, *args, **kwargs):
        kwargs['namespace'] = self.namespace
        return self.smap_instance.add_timeseries(self.join_id(path), *args, **kwargs)
    def add_collection(self, id, collection):
        self.smap_instance.add_collection(self.join_id(id), collection, 
                                          namespace=self.namespace)


class BaseDriver:
    implements(ISmapDriver)
    def setup(self, inst, opts):
        # generating uuids like this is guaranteed to give is the same result every time

        # because the root (/) uuid is actually the uuid of the
        # attachment point of the driver.  This uuid should be either
        # stored in the config file or also generated
        # deterministically from a root uuid.
        #
        # Therefore changing the root uuid will change all the uuids in the tree.
        self.t = inst.add_timeseries('/sensor0', 'mytimeseries', 'SDH')
        self.inst = inst
        self.t['Metadata'] = { 
            'Instrument' : {'ModelName' : 'PowerScout 18'},
            'Extra' : { 'ModbusAddr' : opts.get('ModbusAddr', '')}
            }

    def start(self):
        self.counter = 0
        util.periodicCallInThread(self.read).start(1)

    def read(self):
        self.t.add(self.counter)
        self.counter += 1
        print self.counter


if __name__ == '__main__':
    # inst = loader.load('default.ini', autoflush=False)
    # d = SmapDriverManager.get_driver('driver.BaseDriver', '/newsensor')
    # d.setup(inst)
    import uuid
    inst = core.SmapInstance(uuid.uuid1())
    bd = BaseDriver()
    bd.setup(inst, {})
    inst.start()

    server.run(inst)
