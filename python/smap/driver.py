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

import uuid
import datetime
import time
import sys
from twisted.internet import reactor, threads, defer
from zope.interface import implements

from interface import *
import core
import util
import loader
import server
from smap.contrib import dtutil

class SmapDriver:
    # this is actually a shim layer which presents a ISmapInstance to
    # drivers
    implements(ISmapInstance)
    load_chunk_size = datetime.timedelta(days=1)

    @classmethod
    def get_driver(cls, inst, name, attach_point, namespace):
        """Create a managed driver which will manage a driver whose
        implementation is named by "name"
        """
        cmps = name.split('.')
        assert len(cmps) > 1
        (mod_name, class_name) = ('.'.join(cmps[:-1]), cmps[-1])

        if mod_name in sys.modules:
            mod = sys.modules[mod_name]
        else:
            mod = __import__(mod_name, globals(), locals(), [class_name]) 

        klass = getattr(mod, class_name)
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
        return self.add_timeseries(path, unit, klass=klass, **kwargs)
    def add_collection(self, path, *args):
        self.__inst.add_collection(self.__join_id(path), *args)
    def set_metadata(self, id, *metadata):
        return self.__inst.set_metadata(self.__join_id(id), *metadata)
    def add(self, id, *args):
        return self.__inst.add(self.__join_id(id), *args)
    def _add(self, id, *args):
        return self.__inst._add(self.__join_id(id), *args)
    def uuid(self, key):
        return self.__inst.uuid(key, namespace=self.namespace)

    def load(self, startdt, enddt):
        """Default load method tries to call update with one-day chunks"""
        self.start_dt = startdt
        self.end_dt = enddt
        return self._load_time_chunk(self)

    def _load_time_chunk(self, *args):
        if self.start_dt >= self.end_dt:
            return None

        # pick a new window
        start = self.start_dt
        end = self.start_dt + self.load_chunk_size
        if end > self.end_dt: end = self.end_dt

        print "loading", self.start_dt, '-', self.end_dt
        self.start_dt = self.start_dt + self.load_chunk_size
        print start, end
        d = defer.maybeDeferred(self.update, start, end)
        d.addCallback(self.update)
        d.addCallback(lambda _: self._flush())
        d.addCallback(self._load_time_chunk)

        def err(e):
            print e
        d.addErrback(err)

        return d


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
