
import uuid
import shelve
import operator
import datetime

import numpy as np

from twisted.internet import reactor, threads
from smap import driver, util, smapconf
from smap.archiver.client import SmapClient, RepublishClient
from smap.contrib import dtutil

# null vector with the right shape so we can index into it
null = np.array([])
null = np.reshape(null, (0, 2))

OP_N_TO_1 = 1
OP_N_TO_N = 2

class Operator:
    # data type of operator output
    data_type = ('double', float)

    def __init__(self, inputs, outputs=OP_N_TO_1):
        """
        :param inputs: list of uuids the operator examines
        """
        self.inputs = inputs
        self._has_pending = False
        self._pending = [np.array([])] * len(inputs)

        # auto-construct output ids if requested
        if outputs == OP_N_TO_1:
            self.outputs = [reduce(lambda x, y: str(uuid.uuid5(y, x)), 
                                   map(uuid.UUID, self.inputs), 
                                   self.name)]
        elif outputs == OP_N_TO_N:
            self.outputs = map(lambda x: str(uuid.uuid5(x, self.name)),
                               map(uuid.UUID, self.inputs))
        else:
            self.outputs = outputs

    def _name(self):
        """Return a stringified name for the operator"""
        raise NotImplementedError()

    name = property(_name)

    def __call__(self, input):
        return self.process(input)

    def reset(self):
        """Reset the internal state to discard any changes made"""
        raise NotImplementedError()

    def process(self, recs):
        """Process a number of records in bulk

:param list recs: a list of (timestamp, value) tuples
:return list: a list of (timestamp, value)  """
        raise NotImplementedError()

    def _push(self, stream, data):
        """Insert data for a single stream"""
        self._pending[self.inputs.index(stream)] = data
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
    load_chunk_size = datetime.timedelta(days=1)

    def add_operator(self, path, op, unit):
        """Add an operator to the driver
        """
        if len(op.outputs) != 1:
            raise SmapException("Can only add operators with a single output!")
        opid = op.outputs[0]
        if not isinstance(opid, uuid.UUID):
            opid = uuid.UUID(opid)

        self.add_timeseries(path, opid, unit, 
                            data_type=op.data_type[0],
                            milliseconds=False)
        self.set_metadata(path, {
                'Extra/SourceStream' : str(op.inputs[0]),
                'Extra/Operator' : str(op.name)
                })

        for source in op.inputs:
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

    def _data(self, data):
        """Process incoming data by pushing it through the operators
        """
        print "_data", len(data)
        for v in data.itervalues():
            if not 'uuid' in v: 
                continue
            source_id = str(v['uuid'])
            if not source_id in self.operators: 
                continue

            data = v['Readings']
            if not isinstance(data, np.ndarray):
                data = np.array(data)
            data[:,0] /= 1000

            # push all data through the appropriate operators
            for addpath, op in self.operators[source_id].itervalues():
                op._push(source_id, data)

        for addpath, op in self.oplist:
            new = op._process()
            for newv in new[0]:
                ts, v = int(newv[0]), op.data_type[1](newv[1])
                # print "adding", addpath, newv
                self._add(addpath, ts, v)

    def setup(self, opts, restrict=None, shelveoperators=True, cache=True):
        self.source_url = opts.get('SourceUrl', 'http://smote.cs.berkeley.edu:8079')
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
                self.add_operator(path, op, '')

    def start(self):
        """Start receiving real-time data when used in daemon mode"""
        # set up clients to provide the data
        self.client = RepublishClient(self.source_url, self._data, 
                                      restrict=self.restrict)
        self.client.connect()

        # can have multiple sources
        # RepublishClient('http://local.cs.berkeley.edu:8079', self.data).connect()

    def load(self, start_dt, end_dt):
        """Load a range of time by pulling it from the database and
        pushing it through the operators"""
        print "starting load..."
        self.load_uids = self.operators.keys()
        self.start_dt, self.end_dt = start_dt, end_dt
        return self.load_time_chunk(self)

    def load_time_chunk(self, *args):
        if self.start_dt >= self.end_dt:
            return None

        # pick a new window
        start = self.start_dt
        end = self.start_dt + self.load_chunk_size
        if end > self.end_dt: end = self.end_dt

        start, end  = dtutil.dt2ts(start), \
            dtutil.dt2ts(end)

        print "loading", self.start_dt, '-', self.end_dt
        self.start_dt = self.start_dt + self.load_chunk_size

        d = threads.deferToThread(self.arclient.data_uuid, 
                                  self.load_uids,
                                  start, end, self.cache)
        d.addCallback(self.load_data)
        d.addCallback(self.load_time_chunk)
        return d

    def load_data(self, data):
        dobj = {'/%s' % str(uid): {
                'uuid' : str(uid), 
                'Readings' : dv} for uid, dv in zip(self.load_uids, data)}
        self._data(dobj)


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
        OperatorDriver.setup(self, opts, self.restrict, shelveoperators=False)

        # look up the streams, units, and group tags.
        client = SmapClient()
        streams = client.tags(self.restrict, 'uuid, Properties/UnitofMeasure, %s' % self.group)
        groupitems = {}

        # find the groups
        for s in streams:
            if not s[self.group] in groupitems:
                groupitems[s[self.group]] = []
            groupitems[s[self.group]].append(s)

        # instantiate one operator per group with the appropriate inputs
        for group, tags in groupitems.iteritems():
            inputs = map(operator.itemgetter('uuid'), tags)
            units = set(map(operator.itemgetter('Properties/UnitofMeasure'), tags))
            if len(units) != 1:
                raise SmapException("Group units differ in group %s: %s" % (
                        group, str(units)))

            op = self.operator_class(inputs)
            path = '/' + util.str_path(group)
            self.add_operator(path, op, tags[0]['Properties/UnitofMeasure'])
            self.set_metadata(path, {
                    self.group: group
                    })


class ParallelSimpleOperator(Operator):
    """Parent class for operators which can be applied separately to
    each stream.  Create a classmethod called `base_operator` which
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

    def process(self, input):
        return self.op(input)


def parallelize(operator, n, **initargs):
    """Parallelize operators which perform identically on n input
    streams.
    """
    state = [initargs] * n
    def _parallelized(inputs, *kwags):
        rv = [None] * n
        for i in xrange(0, n):
            rv[i], state[i] = operator(inputs[i], **state[i])
        return rv
    return _parallelized

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
        Operator.__init__(self, inputs, _inputs)

    def process(self, data):
        rv =  reduce(lambda x, y: y(x), self.ops, data)
        return rv

