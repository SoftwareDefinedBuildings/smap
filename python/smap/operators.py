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
import shelve
import operator
import datetime
import copy
import itertools

import numpy as np

from twisted.internet import reactor, threads
from twisted.python import log
from smap import driver, util, smapconf
from smap.core import SmapException
from smap.archiver.client import SmapClient, RepublishClient
from smap.contrib import dtutil
from twisted.spread import pb

from dateutil.tz import gettz

# null vector with the right shape so we can index into it
null = np.array([])
null = np.reshape(null, (0, 2))

def mknull(n):
    a = np.array([])
    return np.reshape(a, (0, n))

OP_N_TO_1 = 1
OP_N_TO_N = 2

class DataChunk(list):
    """Wrapper object holding raw time series data being processed

    The chunk boundaries contains an (start, end) tuple of timestamps 
    """
    def __init__(self, region, first, last, *args, **kwargs):
        # the time window being processed
        self.region = region
        # if this is the first and/or last chunk of data -- can be used to flush buffers
        self.first, self.last = first, last
        list.__init__(self, *args, **kwargs)


class Operator(object):
    # data type of operator output
    data_type = ('double', float)
    required_tags = set(['uuid'])
    optional_tags = set([])
    block_streaming = False

    def __init__(self, inputs, 
                 outputs=OP_N_TO_1, 
                 tags=None):
        """
        :param inputs: list of uuids the operator examines
        """
        self.inputs = inputs
        self.tags = tags
        self._has_pending = False
        self._pending = [null] * len(inputs)

        uuids = map(operator.itemgetter('uuid'), inputs)

        # auto-construct output ids if requested
        if outputs == OP_N_TO_1:
            self.outputs = [util.dict_all(inputs)]
            self.outputs[0]['uuid'] = reduce(lambda x, y: str(uuid.uuid5(y, x)), 
                                             map(uuid.UUID, sorted(uuids)), 
                                             self.name)
        elif outputs == OP_N_TO_N:
            self.outputs = copy.deepcopy(inputs)
            for i, uid in enumerate(map(lambda x: str(uuid.uuid5(x, self.name)),
                                        map(uuid.UUID, uuids))):
                self.outputs[i]['uuid'] = uid
        else:
            self.outputs = copy.deepcopy(outputs)

    def index(self, streamid):
        for i in xrange(0, len(self.inputs)):
            if self.inputs[i]['uuid'] == streamid:
                return i
        return None

#     @name.setter
#     def _get_name(self):
#         """Return a stringified name for the operator"""
#         if self._name:
#             raise NotImplementedError()
#         else:
#             return self._name

#     @name.


    def __call__(self, input, **kwargs):
        if not isinstance(input, DataChunk):
            input = DataChunk((None, None), False, False, input)
        return self.process(input, **kwargs)

    def reset(self):
        """Reset the internal state to discard any changes made"""
        raise NotImplementedError()

    def process(self, recs):
        """Process a number of records in bulk

:param list recs: a list of (timestamp, value) tuples
:return list: a list of (timestamp, value)  """
        raise NotImplementedError()

    def _push(self, stream, data, stream_idx=None):
        """Insert data for a single stream"""
        if not stream_idx: stream_idx = self.index(stream) 
        self._pending[stream_idx] = data
        self._has_pending = True

    def _process(self):
        """Deliver all waiting data."""
        if self._has_pending: 
            rv = self.process(self._pending)
            self._pending = [null] * len(self.inputs)
            self._has_pending = False
            return rv
        else:
            return [null] * len(self.inputs)

    def __str__(self):
        return self.name

class OperatorDriver(driver.SmapDriver):
    """Base class for code which wants to process single streams.

    To do this you should:

     a) implement an :py:class:`Operator`, which contains your
      specific logic.  You should at least override name() to provide
      a human-readable name for your operator, and and bulk() which
      processes chunks of data..
     b) subclass OperatorDriver, implementing a "setup" method which
      creates operators and adds them using :py:method:`add_operator`.
      Make sure you call OperatorDriver.setup.

    If you do this, you'll be able to use your operator both in
    real-time mode (via a twistd smap source) and to run on historical
    data, using `smap-load` to load source data and pipe it through
    operators.
    """
    load_xsec_size = 200

    def add_operator(self, path, op, inherit_metadata=False):
        """Add an operator to the driver
        """
        if len(op.outputs) != 1 or not 'Properties/UnitofMeasure' in op.outputs[0]:
            raise SmapException("Can only add operators with a single output!")
        opid = op.outputs[0]['uuid']
        unit = op.outputs[0]['Properties/UnitofMeasure']
        if not isinstance(opid, uuid.UUID):
            opid = uuid.UUID(opid)

        self.add_timeseries(path, opid, unit, 
                            data_type=op.data_type[0],
                            milliseconds=False)

        self.set_metadata(path, {
                'Extra/SourceStream' : \
                    ','.join(map(operator.itemgetter('uuid'), op.inputs)),
                'Extra/Operator' : str(op.name)
                })
        if inherit_metadata:
            self.set_metadata(path, op.outputs[0])

        for source in op.inputs:
            source = source['uuid']
            if not source in self.operators:
                self.operators[source] = {}
            if not opid in self.operators[source]:
                self.operators[source][opid] = (path, op)
        self.oplist.append((path, op))

    def reset(self):
        """Reset all operators"""
        for oplist in self.operators.itervalues():
            for path, op in oplist.itervalues():
                op.reset()

    def _data(self, uuids, newdata, process=True):
        """Process incoming data by pushing it through the operators
        
        process: don't actually process the operators, just add the
           pending data.
        """
        # print "_data", len(newdata)
        pushlist = set([])
        for source_id, data in zip(uuids, newdata):
            if not source_id in self.operators: 
                continue

            # prepare the data
            if len(data) == 0:
                data = np.reshape(data, (0, 2))

            # push all data through the appropriate operators
            for addpath, op in self.operators[source_id].itervalues():
                op._push(source_id, data)
                pushlist.add((addpath, op))

        if not process: return
        pushlist = list(pushlist)
        pushlist.sort(key=lambda x: x[0])

        for addpath, op in pushlist:
            new = op._process()
            for newv in new[0]:
                ts, v = int(newv[0]), op.data_type[1](newv[1])
                self._add(addpath, ts / 1000, v)

    def setup(self, opts, restrict=None, shelveoperators=False, cache=True, raw=False):
        self.load_chunk_size = datetime.timedelta(hours=int(opts.get('ChunkSize', 24)))
        self.source_url = opts.get('SourceUrl', 'http://new.openbms.org/backend')
#        self.source_url = opts.get('SourceUrl', 'http://ar1.openbms.org:8079')
        if not raw and restrict:
            self.restrict = '(' + restrict + ') and not has Metadata/Extra/Operator'
        else:
            self.restrict = restrict

        if shelveoperators:
            self.operators = shelve.open(opts.get('OperatorCache', '.operators'),
                                         protocol=2, writeback=True)
            # sync the operator state periodically and at exit
            util.periodicCallInThread(self.operators.sync).start(60)
            reactor.addSystemEventTrigger('after', 'shutdown', 
                                          self.operators.close)
        else:
            self.operators = {}
            self.oplist = []
        self.arclient = SmapClient(self.source_url)
        self.cache = cache

        # create timeseries from cached operator state
        for sid, oplist in self.operators.iteritems():
            for path, op in oplist.itervalues():
                self.add_operator(path, op)

    def start(self):
        """Start receiving real-time data when used in daemon mode"""
        # set up clients to provide the data
        source = [
            'http://ar1.openbms.org:8079',
            'http://ar2.openbms.org:8079']
        self.clients = []
        for url in source:
            self.clients.append(RepublishClient(url, self._data, 
                                                restrict=self.restrict))
            self.clients[-1].connect()

    def load(self, start_dt, end_dt, cache=True):
        """Load a range of time by pulling it from the database and
        pushing it through the operators"""
        self.load_uids = self.operators.keys()
        self.start_dt, self.end_dt = start_dt, end_dt
        self.cache = cache
        return self.load_time_chunk(self)

    def load_time_chunk(self, *args):
        if self.start_dt >= self.end_dt:
            return None

        self.load_offset = 0
        return self.load_crossection()

    def load_crossection(self, *args):
        start = self.start_dt
        end = self.start_dt + self.load_chunk_size
        if end > self.end_dt: end = self.end_dt

        log.msg("loading " + str(self.load_offset) + " " +
                str(start) + ' - ' + str(end))
        start, end  = dtutil.dt2ts(start), \
            dtutil.dt2ts(end)

        d = threads.deferToThread(self.arclient.data_uuid, 
                                  self.load_uids[self.load_offset:
                                                     self.load_offset + 
                                                 self.load_xsec_size],
                                  start, end, 
                                  self.cache)

        d.addCallback(self.load_data, self.load_offset)
        d.addCallback(lambda _: (self._flush(), None))

        self.load_offset += self.load_xsec_size
        if self.load_offset >= len(self.load_uids):
            # pick a new window
            self.start_dt += self.load_chunk_size
            d.addCallback(self.load_time_chunk)
        else:
            d.addCallback(self.load_crossection)
        def err(e):
            print e
        d.addErrback(err)

        return d

    def load_data(self, data, offset):
        uuids = self.load_uids[offset:offset+self.load_xsec_size]
        self._data(uuids, data)


class GroupedOperatorDriver(OperatorDriver):
    """Driver which selects streams using a `Restrict` tag selector,
    and groups them according to a `Group` tagname.` It runs one
    operator per group, and send data from each stream to the proper
    operator.

    Make self.operator_class a staticmethod which instantiates a new
    operator.
    """
    operator_class = None

    def setup(self, opts):
        self.restrict = opts.get("Restrict")
        self.group = opts.get("Group")
        self.opstr = opts.get("Operator")
        OperatorDriver.setup(self, opts, self.restrict, shelveoperators=False)

        # look up the streams, units, and group tags.
        client = SmapClient()
        streams = client.tags(self.restrict, '*')
                              # 'uuid, Properties/UnitofMeasure, Metadata/SourceName, %s' % 
                              # self.group)
        #print streams
        groupitems = {}

        # find the groups
        for s in streams:
            if not s[self.group] in groupitems:
                groupitems[s[self.group]] = []
            groupitems[s[self.group]].append(s)

        # instantiate one operator per group with the appropriate inputs
        for group, tags in groupitems.iteritems():
            inputs = map(operator.itemgetter('uuid'), tags)
            op = self.operator_class(tags)
            path = '/' + util.str_path(group)
            self.add_operator(path, op)


##############################################################################
##
## Operators for the framework
##
##############################################################################

def extend(a1, a2):
    """Extend data vector a1 with vector a2"""
    assert(len(a1) == len(a2))
    rv = [None] * len(a1)
    for i in xrange(0, len(a2)):
        if a1[i].shape[0] == 0:
            rv[i] = a2[i]
        elif len(a2[i]):
            rv[i] = np.vstack((a1[i], a2[i]))
        else:
            rv[i] = a1[i]
    return rv

def join_intersect(inputs, last=None):
    """Join together streams based on timestamps, throwing out places
    where they do not overlap"""
    times = reduce(lambda x, y: np.intersect1d(x, y[:,0]), inputs)
    vals = map(lambda x: x[np.nonzero(np.in1d(x[:,0], times)), :][0]
               if len(x) else null, inputs)
    return vals 

def join_union(inputs):
    """Join together streams based on timestamps, including all data
    and inserting np.nan for missing values into each stream"""
    if len(inputs) == 1: return inputs
    times = reduce(lambda x, y: np.union1d(x, y[:, 0]), inputs[1:], 
                   inputs[0][:, 0])
    times = np.reshape(times, (len(times), 1))
    rv = []
    for stream in inputs:
        new = np.column_stack((times, 
                               np.ones((len(times), stream.shape[1] - 1)) * np.nan))
        if stream.shape[0] > 0:
            new[np.nonzero(np.in1d(times, stream[:, 0])), 1:] = stream[:, 1:]
        rv.append(new)
    return rv

def transpose_streams(inputs):
    """Takes aligned inputs and returns a matrix with t, v1, v2, ... vN"""
    data = np.hstack(map(lambda x: x[:, 1:], inputs))
    return np.vstack((inputs[0][:, 0], data.T)).T


class ParallelSimpleOperator(Operator):
    """Parent class for operators which can be applied separately to
    each stream.  Create a staticmethod called `base_operator` which
    performs the appropriate operation when called on a single stream

    Any keyword args will be passed to this classmethod on invocation;
    it needs to have a special form: it should take as an argument a
    data vector, and return a (result, kwarg) tuple.  The tuple will
    be passed to the operator on the next invocation.
    """
    def __init__(self, inputs, **initargs):
        Operator.__init__(self, inputs, outputs=OP_N_TO_N)
        self.op = parallelize(self.base_operator, 
                              len(inputs),
                              **initargs)

    def process(self, input, **kwargs):
        return self.op(input, **kwargs)


class parallelize(object):
    def __init__(self, operator, n, *opargs, **initargs):
        self.operator = operator
        self.n = n
        self.opargs = opargs
        self.state = [initargs] * n

    def __call__(self, inputs):
        rv = [None] * self.n
        assert self.n == len(inputs)
        for i in xrange(0, self.n):
            opdata = self.operator(inputs[i], *self.opargs, **self.state[i])
            if isinstance(opdata, tuple):
                rv[i], self.state[i] = opdata
            else:
                rv[i] = opdata
        return rv


class VectorOperator(Operator):
    """Base class for operators which can work on either axis.

    It will automatically allow you to apply your operator either
    across streams or across all data from separate streams in
    parallel.  If the operator can operate on multiple vectors in
    parallel (a la many numpy operators), the base operator should
    have the 'parallel' attribute set on it.

    The operators may either return just a numpy array as a result, or
    a (result, state) tuple; the state gets passed as kwargs on the
    next execution.

    This style of operator is only useful over a finite time period,
    so as the inner operator of a windowing operator or to answer a
    query like "max" or "min" over a date range.
    """
    name = 'vector operator'

    def __init__(self, inputs, *opargs, **initargs):
        self.axis = 0 if initargs.get('axis', 'time') in ['time', 0] else 1
        initargs['axis'] = self.axis
        self.name = "%s(%s)" % (self.name, 
                                ",".join(list(map(str, opargs)) +
                                         map(lambda (k, v): str(k) + "=" + str(v), 
                                             initargs.iteritems())))

        # if we operate in parallel then we also produce n output
        # operators
        outputs = OP_N_TO_N
        self.block_streaming = (self.axis == 0)
            
        self.op = parallelize(self.base_operator,
                              len(inputs),
                              *opargs,
                              **initargs)
        Operator.__init__(self, inputs, outputs=outputs)

    def process(self, inputs):
        return self.op(inputs)


class CompositionOperator(Operator):
    """Set an oplist property of a class instance of this, or a
    subclass The oplist should be a list of operator constructors;
    when passed in data, this class will chain the operators together
    and become an operator of their compsition.
    """
    def __init__(self, inputs):
        self.ops = []
        _inputs = inputs
        for opclass in self.oplist:
            op = opclass(_inputs)
            self.ops.append(op)
            _inputs = op.outputs
        self.required_tags = set.union(*map(lambda x: x.required_tags, self.ops))
        self.optional_tags = set.union(*map(lambda x: x.optional_tags, self.ops))
        self.block_streaming = reduce(operator.__or__,
                                      map(operator.attrgetter('block_streaming'), self.ops))

        Operator.__init__(self, inputs, _inputs)

    def process(self, data):
        return reduce(lambda x, y: y(x), self.ops, data)

    def __str__(self):
        return ' < '.join(map(str, reversed(self.ops)))

def make_composition_operator(ops):
    class _TmpOp(CompositionOperator):
        name = 'none'
        oplist = ops
    return _TmpOp
