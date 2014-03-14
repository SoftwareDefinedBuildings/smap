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

import os
import uuid
from zope.interface import implements
from twisted.web import resource
from twisted.internet import reactor, defer
import exceptions
import sys
import operator
import time 

from smap import schema
from smap import util
from smap import reporting
from smap import smapconf
from smap import actuate
from smap import jobs
from smap.interface import *
from smap.checkers import datacheck


class SmapException(Exception):
    """Generic error"""
    def __init__(self, message, http_code=None):
        Exception.__init__(self, message)
        self.http_code = http_code

class SmapSchemaException(SmapException):
    """Exception generated if a json object doesn't validate as the
appropriate kind of schema"""

class Timeseries(dict):
    """Represent a single Timeseries.  A Timeseries is a single stream of
    scalars, with associated units.

    The sMAP profile requires each time series to be associated with a
    data type (long or double), unit of measure, and
    timezone.
    """
    implements(ITimeseries)

    FIELDS = ["Readings", "Description", "Metadata", 
              "Properties", "uuid"]

    # default values for the initializer  
    # these are used both here and when the loader module creates a
    # sMAP instance from a config file
    DEFAULTS = {
        'BufferSize' : 1,
        'Properties/Timezone' : 'America/Los_Angeles',
        'Properties/ReadingType' : 'long'
        }

    def __init__(self,
                 new_uuid,
                 unit, 
                 data_type=DEFAULTS['Properties/ReadingType'],
                 timezone=DEFAULTS['Properties/Timezone'],
                 description=None,
                 buffersz=DEFAULTS['BufferSize'],
                 milliseconds=False,
                 impl=None, 
                 read_limit=0,
                 write_limit=0,
                 autoadd=False):
        """
:param new_uuid: a :py:class:`uuid.UUID`
:param string unit: the engineering units of this timeseries
:param string data_type: the data type of the data. Options are ``long`` or ``double``
:param string timezone: a tzinfo-style timezone.
:param string description: the value of sMAP Description field.
:param int buffersz: how many readings to present when the timeseries is retrieved with a ``GET``.
:param bool milliseconds: if True, then the stream publishes time in
 units of Unix milliseconds.  Otherwise, normal unix timestamps are
 assumed
"""
        if isinstance(new_uuid, dict):
            if not schema.validate('Timeseries', new_uuid):
                raise SmapSchemaException("Initializing timeseries failed -- invalid object")
            dict.__init__(self, new_uuid)
            reading_init = new_uuid['Readings']
        else:
            self.__setitem__("uuid", new_uuid)
            self.__setitem__("Properties", {
                    'UnitofMeasure' : unit,
                    'ReadingType' : data_type,
                    'Timezone' : timezone})
            if description:
                self.__setitem__("Description", description)
            reading_init = []
        self.dirty = True
        self.milliseconds = milliseconds
        self.__setitem__("Readings", util.FixedSizeList(buffersz, init=reading_init))

        self.impl = impl
        self.autoadd = autoadd
        if self.impl:
            self.reader = util.RateLimiter(read_limit, 
                                      lambda req: util.syncMaybeDeferred(self.impl.get_state, req),
                                      lambda req: self)
            self.writer = util.RateLimiter(write_limit, 
                                      lambda req, state: util.syncMaybeDeferred(self.impl.set_state, req, state))
        else:
            self.reader = lambda req: (True, self)
            self.writer = None

    def _check_type(self, value):
        type_ = self.__getitem__('Properties')['ReadingType']
        if type_ == 'long' and util.is_integer(value):
            return True
        elif type_ == 'double' and \
                isinstance(value, float):
            return True
        else:
            return False

    def _add(self, *args):
        """Add a new reading to this timeseries.  This version must
only be called from the :py:mod:`twisted` main loop; *i.e.* from a
callback added with ``reactor.callFromThread()``

Can be called with 1, 2, or 3 arguments.  The forms are

* ``_add(value)``
* ``_add(time, value)``
* ``_add(time, value, seqno)``

:raises SmapException: if the value's type does not match the stream
 type, or was called with an invalid number of arguments.
        """
        seqno = None
        if len(args) == 1:
            time = util.now()
            if self.milliseconds: time *= 1000
            value = args[0]
        elif len(args) == 2:
            time, value = args
        elif len(args) == 3:
            time, value, seqno = args
        else:
            raise SmapException("Invalid add arguments: must be (value), "
                                "(time, value), or (time, value, seqno)")

        # note that we got data now
        self.inst.statslog.mark()

        time = int(time)
        if not self.milliseconds:
            time *= 1000

        if not self._check_type(value):
            raise SmapException("Attempted to add " + str(value) + 
                                " to Timeseries, but " +
                                "the timeseries type is " + 
                                self.__getitem__('Properties')['ReadingType'])
        
        if seqno: reading = time, value, seqno
        else: reading = time, value
        self["Readings"].append(reading)
        if not hasattr(self, 'inst'): return

        # if a timeseries is dirty, we need to republish all of its
        # metadata before we publish it so stream is right. some of
        # this may have already been published, in which case it won't
        # actually do anything.
        if self.dirty:
            split_path = util.split_path(getattr(self, 'path'))
            for i in xrange(0, len(split_path)):
                path_seg = util.join_path(split_path[:i])
                self.inst.reports.publish(path_seg, 
                                          self.inst.get_collection(path_seg))
            rpt = dict(self)
            rpt['Readings'] = [reading]
            self.inst.reports.publish(getattr(self, 'path'), rpt)
            self.dirty = False
        else:
            # publish a stripped-down Timeseries object
            self.inst.reports.publish(getattr(self, 'path'),
                                      {'uuid' : self['uuid'],
                                       'Readings' : [reading]})

    def add(self, *args):
        """A version of :py:meth:`~Timeseries._add` which can be called from any thread.
        """
        # SDH : thread-safe
        # this way the real add is always done in the main loop,
        # even if it was called by another threadpool or something.
        reactor.callFromThread(lambda: self._add(*args))

    def __setitem__(self, attr, value):
        if attr in self.FIELDS:
            dict.__setitem__(self, attr, value)
            if attr != 'uuid':
                if not schema.validate("Timeseries", self):
                    raise SmapSchemaException("Invalid schema in " 
                                              "Timeseries for " + 
                                              attr)
            # time series start dirty so when we publish them the
            # first time we send all their metadata.
            self.dirty = True
        else:
            raise KeyError(attr + " can not be set on a Timeseries!")

    def set_metadata(self, metadata):
        metadata = util.build_recursive(metadata)
        if 'Metadata' in metadata:
            metadata = metadata['Metadata']
        self['Metadata'] = util.dict_merge(self.get('Metadata', {}),
                                           metadata)

    def render(self, request):
        if request.method == 'GET':
            return self.render_read(request)
        elif request.method == 'PUT':
            return self.render_write(request)

    def render_write(self, request):
        """Render a request to change the state"""
        if 'state' in request.args and len(request.args['state']) > 0:
            new_state = self.impl.parse_state(request.args['state'][0])
            if not self.impl.valid_state(new_state):
                raise SmapException("Invalid state: " + str(new_state), 400)

            allowed, rv = self.writer(request, new_state)
            if allowed:
                if not issubclass(rv.__class__, defer.Deferred):
                    rv = defer.succeed(rv)
                rv.addCallback(lambda x: self._finish_render(request, x))
                return rv
            else:
                raise SmapException("Cannot actuate now due to rate limit\n", 503)

    def render_read(self, request):
        """Render the read

        The rate limiter will make sure that we don't overload the
        device; it will used the Timeseries cached value if we've
        called it too much.
        """
        allowed, rv = self.reader(request)
        if allowed:
            if not issubclass(rv.__class__, defer.Deferred):
                rv = defer.succeed(rv)
            rv.addCallback(lambda x: self._finish_render(request, x))
            return rv
        else:
            raise SmapException("Cannot actuate now due to rate limit", 503)

    def _finish_render(self, request, state):
        # finish by adding the current state as the reading
        if isinstance(state, dict):
            return state
        elif hasattr(state, "__iter__"):
            now, val = state
        else:
            now, val = util.now() * 1000, state

        try:
            val = self.impl.translate_state(state)
        except Exception, e:
            raise SmapException("Error processing write result: " + str(e), 500)

        if self.autoadd:
            self._add(now, state)
            return self
        else:
            ts = dict(self)
            ts['Readings'] = [(now, val)]
            return ts

class Collection(dict):
    """Represent a collection of sMAP resources"""
    implements(ICollection)
    def __init__(self, path, inst=None, description=None, *args):
        """
        :param string path: the path where the collection will be added
        :param SmapInstance inst: the containing :py:class:`SmapInstance` object
        :param string description: the contents of the sMAP description field
        :raise SmapSchemaException: if the resulting object does not validate
        """
        self.inst = inst
        setattr(self, 'path', util.norm_path(path))
        if len(args) == 1 and isinstance(args[0], dict):
            dict.__init__(self, args[0])
        else:
            self.__setitem__("Contents", [])

        if not schema.validate("Collection", self):
            raise SmapSchemaException("Error instantiating Collection: " 
                                      "invalid parameter")

    def add_child(self, name):
        """Add a child name to the collection
        """
        self["Contents"].append(name)

    def dirty_children(self):
        """Recursively mark all timeseries contained in this collection as dirty
        """
        def explore(item, path):
            if not 'Contents' in item:
                item.dirty = True
            else:
                for ps in item['Contents']:
                    newpath = path + [ps]
                    explore(self.inst.lookup(util.join_path(newpath)), 
                            newpath)
        if hasattr(self, 'path'):
            explore(self, util.split_path(getattr(self, 'path')))

    def __setitem__(self, attr, value):
        if not attr in ['Contents', 'Metadata', 'Proxy']:
            raise SmapException("Key " + attr + " cannot be set on a Collection!")
        elif not attr in self or value != dict.__getitem__(self, attr):
            self.dirty_children()
            dict.__setitem__(self, attr, value)
            self.dirty_children()

    def update(self, val):
        if 'Contents' in val:
            del val['Contents']
        dict.update(self, val)

    def set_metadata(self, metadata):
        metadata = util.build_recursive(metadata)
        if 'Metadata' in metadata:
            metadata = metadata['Metadata']
        self['Metadata'] = util.dict_merge(self.get('Metadata', {}),
                                           metadata)
        self.dirty_children()

    def render(self, request):
        return self

class LoggingTimeseries(object):
    def __init__(self):
        self.last = None

    def mark(self):
        self.last = time.time()

    def latest(self):
        return self.last

class SmapInstance:
    """A sMAP instance is a tree of :py:class:`Collections` and
:py:class:`Timeseries`.  A :py:class:`SmapInstance` allows lookups
based on either path or UUID, and also contains a reference to the
sMAP reporting functionality."""
    implements(ISmapInstance)

    def __init__(self, root_uuid, **kwargs):
        if not isinstance(root_uuid, uuid.UUID):
            root_uuid = uuid.UUID(root_uuid)

        self.OBJS_PATH = {}
        self.OBJS_UUID = {}
        self.drivers = {}
        # this contains elements of the form [function, timebetweenruns] to
        # allow loader to hook in checking functions.
        self.checkers = []
        # whole-instance stats log for testing
        self.statslog = LoggingTimeseries()


        # if we're not given an explicit report file, put it in the
        # datadir or else the cwd
        if not 'reportfile' in kwargs:
            if 'datadir' in smapconf.SERVER:
                rf = os.path.join(smapconf.SERVER['datadir'], str(root_uuid))
            else:
                rf = str(root_uuid)

            self.reports = reporting.Reporting(self, reportfile=rf, **kwargs)
        else:
            self.reports = reporting.Reporting(self, **kwargs)
        self.flush = self.reports.flush
        self._flush = self.reports._flush
        self.loading = False
        self.add_collection("/")
        self.root_uuid = root_uuid

    # keep a list of sensor drivers so we can find them easily
    def add_driver(self, path, driver):
        self.drivers[path] = driver

    def start(self):
        """Causes the reporting subsystem and any drivers to be started
        """
        map(lambda x: x.start(), self.drivers.itervalues())

        # set all checkers that loader has hooked in to be run on the
        # given interval
        checkstarter = lambda period, checker: util.periodicCallInThread(checker).start(period)
        for args in self.checkers:
            # wait 300 seconds to start each checker, to prevent startup lag from
            # throwing off the checkers
            reactor.callLater(2, checkstarter, *args)

    def stop(self):
        return defer.DeferredList(map(lambda x: defer.maybeDeferred(x.stop),
                                      self.drivers.itervalues()))

    def uuid(self, key, namespace=None):
        if not namespace:
            namespace = self.root_uuid
        if key and namespace:
            rv = uuid.uuid5(namespace, key)
            if rv in self.OBJS_UUID:
                raise SmapException("Duplicate UUID detected -- this probably "
                                    "means you specifed the same key twice in "
                                    "the same namespace.  The offending key is " + 
                                    str(key))
            return rv
        else:
            raise SmapException("Timeseries cannot generate uuid: must "
                            "specifiy either uuid or key and ROOT_UUID")

    def lookup_path(self, id):
        """Look up the path of Timeseries by uuid
        :param uuid.UUID id: the id of the timeseries in question
        """
        t = self.get_timeseries(id)
        if t and hasattr(t, 'path'):
            return getattr(t, 'path')
        return None
    
    def lookup(self, id, pred=None):
        """Retrieve an object in the resource hierarchy by path or uuid.  If
        *id* is a string not starting with ``/``, it will be passed to the
        :py:class:`uuid.UUID` constructor; otherwise it will be treated as a
        pathname.  *pred* is an optional predicate which can be used to test
        the result.
        """
        if util.is_string(id):
            path = util.split_path(id)
            if len(path) > 0 and path[-1][0] == "+":
                return self._lookup_r(util.join_path(path[:-1]), pred=pred)
            else:
                obj = self.OBJS_PATH.get(util.join_path(path), None)
        elif isinstance(id, uuid.UUID):
            return self.OBJS_UUID.get(id, None)
        else:
            obj = None
        
        if not pred or pred(obj):
            return obj
        else: return None

    def _lookup_r(self, id, pred=None):
        """Lookup recursively in the resource hierarchy, starting with the
        resource identifed by "id".  Returns a list of elements for which
        "pred" returns True"""
        rv = {}
        q = [id]
        root_path = getattr(self.lookup(id), 'path')

        while len(q) > 0:
            cur = self.lookup(q.pop(0))
            if ICollection.providedBy(cur):
                for child in cur['Contents']:
                    q.append(getattr(cur, 'path') + '/' + child)
            if cur and (not pred or pred(cur)):
                rvpath = util.norm_path(getattr(cur, 'path')[len(root_path):])
                rv[rvpath] = cur
        return rv

    @staticmethod
    def render_lookup(request, val):
        """Render a return value of lookup, by calling render()
        methods on all the results.  Returns either the object or a
        deferred that you must wait on for the result to be ready.
        """
        if hasattr(val, "render") and callable(val.render):
            # if its not a collection of objects, just render it
            return val.render(request)
        elif isinstance(val, dict):
            # otherwise we might need to render() multiple objects and
            # wait for all of them -- this can happen if we are
            # reading multiple actuators.
            rv = {}
            deferreds = []

            # start all the rendering
            for k, v in val.iteritems():
                rendered = v.render(request)
                if isinstance(rendered, defer.Deferred):
                    deferreds.append((k, rendered))
                else:
                    rv[k] = rendered
            # set up a deferred task which will fire when all results are ready
            if len(deferreds) == 0:
                return rv
            else:

                # and insert the ones which succeeded into the result
                # set.
                def insertResults(vals):
                    for ((path, d), (success, yld)) in zip(deferreds, vals):
                        if success:
                            rv[path] = yld
                    return rv

                d = defer.DeferredList(map(operator.itemgetter(1), deferreds), consumeErrors=True)
                d.addCallback(insertResults)
                return d

    def get_timeseries(self, path): 
        """Returns a :py:class:`Timeseries` if an object is found
        matching *path*, or None otherwise."""
        return self.lookup(path, pred=ITimeseries.providedBy)

    def get_collection(self, path):
        """Returns a :py:class:`Collection` if an object with an
        identifier matching *path* is found, None otherwise
        """
        return self.lookup(path, pred=ICollection.providedBy)

    def _add(self, path, *args, **kwargs):
        """Utility to call the version of :py:meth:`~smap.core.Timeseries._add`
        associated with *path*.  The same as ``inst.get_timeseries(path)._add(...)``
        """
        return self.get_timeseries(path)._add(*args, **kwargs)
        
    def add(self, path, *args, **kwargs):
        """Utility to call the version of :py:meth:`~smap.core.Timeseries.add`
        associated with *path*.  The same as ``inst.get_timeseries(path).add(...)``
        """
        try:
            return self.get_timeseries(path).add(*args, **kwargs)
        except exceptions.AttributeError, e:
            raise SmapException("add failed: no such path: %s" % path)

    def _add_parents(self, path):
        for i in xrange(0, len(path)):
            if not self.get_collection(util.join_path(path[:i])):
                self.add_collection(util.join_path(path[:i]))

    def add_timeseries(self, path, *args, **kwargs):
        """Add a timeseries to the smap server at the given path.  This will
        generate a UUID for the timeseries.

        direct form 
        :param path a Timeseries instance
        
        simple form 
        :param args[0] is a uuid instance, or a key to generate a uuid with by combining it with the root uuid.
        :param args[1] and kwargs are arguments passed to the Timeseries constructor.  Therefore you have to include at least the UnitofMeasure

        :param boolean replace: (kwarg) replace an existing timeseries at that path instead of throwing an exception
        :param boolean recurse: recursively create parent collections instead of thrwoing an exception.  Default is True.

        :raises: :py:class:`SmapException` if the parent isn't a collection or the path already exists.
        """ 
        replace = kwargs.pop('replace', False)
        recurse = kwargs.pop('recurse', True)
        klass = kwargs.pop('klass', Timeseries)

        if len(args) == 0 or \
                not ITimeseries.providedBy(args[0]) and not IActuator.providedBy(args[0]):
            if len(args) == 2:
                if not isinstance(args[0], uuid.UUID):
                    id = self.uuid(args[0], namespace=kwargs.get('namespace', None))
                else:
                    id = args[0]
                args = args[1:]
            elif len(args) == 1:
                id = self.uuid(util.norm_path(path), kwargs.get('namespace', None))
            else:
                id = self.uuid(util.norm_path(path))
#                 raise SmapException("SmapInstance.add_timeseries may only be called "
#                                     "with two or three arguments")

            kwargs.pop('namespace', None)
            timeseries = klass(id, *args, **kwargs)
            if id != args[0]:
                setattr(timeseries, "key", args[0])
        else:
            timeseries = args[0]

        path = util.split_path(path)
        if recurse: self._add_parents(path)
        parent = self.get_collection(util.join_path(path[:-1]))

        if not replace and util.join_path(path) in self.OBJS_PATH:
            raise SmapException("add_timeseries: path " + str(path) + " exists!")
        if not parent:
            raise SmapException("add_timeseries: parent is not a collection!")
        parent.add_child(path[-1])

        # place the new timeseries into the uuid and path tables
        self.OBJS_UUID[timeseries['uuid']] = timeseries
        self.OBJS_PATH[util.join_path(path)] = timeseries
        timeseries.inst = self
        setattr(timeseries, 'path', util.join_path(path))
        if not self.loading: self.reports.update_subscriptions()
        return timeseries

    def add_collection(self, path, *args): 
        """Add collection to the namespace.  For instance::

          inst.add_collection('/c1')

        :param string path: path under which to add the collection
        :param args[0]: :py:class:`Collection` class to add, if present
        :rtype: the :py:class:`Collection` which was added
        :raises: :py:class:`SmapException` if the parent is not a
         collection, or the path exists.
"""
        if len(args) > 0 and ICollection.providedBy(args[0]):
            collection = args[0]
        elif len(args) == 0:
            collection = Collection(path, self)
        else:
            raise SmapException("add_collection: wrong number of arguments")

        path = util.split_path(path)
        if len(path) > 0:
            parent = self.get_collection(util.join_path(path[:-1]))
            if not parent:
                raise SmapException("add_collection: parent is not collection!")
            parent.add_child(path[-1])
        if util.join_path(path) in self.OBJS_PATH:
            raise SmapException("add_timeseries: path " + str(path) + 
                                " exists!")

        self.OBJS_PATH[util.join_path(path)] = collection
        if not self.loading: self.reports.update_subscriptions()
        return collection

    def add_actuator(self, path, unit, impl, **kwargs):
        ts = self.add_timeseries(path, unit, impl=impl, **kwargs)
        ts.FIELDS = ts.FIELDS + ["Actuator"]
        ts["Actuator"] = impl.get_description()
        if hasattr(self, 'jobs'):
            self.jobs.actuators.append(path)
        else:
            self.jobs = jobs.SmapJobsManager(path, self)
        return ts

    def set_metadata(self, path, *metadata):
        if len(metadata) > 1:
            metadata = dict([metadata])
        else: metadata = metadata[0]

        for v in metadata.itervalues():
            if not util.is_string(v):
                raise SmapException("set_metadata: values must be strings!")

        o = self.lookup(path)
        o.set_metadata(metadata)

    def pause_reporting(self):
        return self.reports.pause()

    def unpause_reporting(self):
        return self.reports.unpause()

if __name__ == '__main__':
    ROOT_UUID = uuid.uuid1()
    s = SmapInstance(ROOT_UUID)
    s.add_collection("/steve")
    t = Timeseries(s.uuid("sdh"), "V", buffersz=2)
    s.add_timeseries("/sensor0", t)
    s.set_metadata("/sensor0", {
            "Foo" : "Bar",
            "Baz" : 10
            })

    t.add(util.now(), 12)
    t.add(util.now(), 13)
    print s.get_timeseries(t['uuid'])
    print s.get_timeseries('/sensor0')
    print s.get_timeseries('/')

#    s.get_collection('/').set_metadata({'Extra' : {"foo": " bar"}})
    print s.get_collection('/')


#     print "Finding all Timeseries under /"
    print s._lookup_r('/', pred=ITimeseries.providedBy)
    print s.lookup('/+Timeseries')

    print s._lookup_r('/', pred=lambda x: x.dirty)

    # print s._lookup_r("/foo")
