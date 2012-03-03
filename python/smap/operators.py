
import uuid
import shelve
import operator
import datetime
import copy
import itertools

import numpy as np

from twisted.internet import reactor, threads
from smap import driver, util, smapconf
from smap.core import SmapException
from smap.archiver.client import SmapClient, RepublishClient
from smap.contrib import dtutil

from dateutil.tz import gettz

# null vector with the right shape so we can index into it
null = np.array([])
null = np.reshape(null, (0, 2))

OP_N_TO_1 = 1
OP_N_TO_N = 2

class Operator:
    # data type of operator output
    data_type = ('double', float)
    required_tags = set(['uuid'])
    optional_tags = set([])

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
    load_chunk_size = datetime.timedelta(hours=4)

    def add_operator(self, path, op):
        """Add an operator to the driver
        """
        if len(op.outputs) != 1:
            raise SmapException("Can only add operators with a single output!")
        # print op.outputs
        opid = op.outputs[0]['uuid']
        unit = op.outputs[0]['Properties/UnitofMeasure']
        # print "Added", opid
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

    def _data(self, data, process=True):
        """Process incoming data by pushing it through the operators
        
        process: don't actually process the operators, just add the
           pending data.
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
            if len(data) == 0:
                data = np.reshape(data, (0, 2))
            data[:,0] /= 1000

            # push all data through the appropriate operators
            for addpath, op in self.operators[source_id].itervalues():
                op._push(source_id, data)

        if not process: return

        for addpath, op in self.oplist:
            new = op._process()
            for newv in new[0]:
                ts, v = int(newv[0]), op.data_type[1](newv[1])
                # print "adding", addpath, newv
                self._add(addpath, ts, v)

    def setup(self, opts, restrict=None, shelveoperators=False, cache=True, raw=False):
        self.source_url = opts.get('SourceUrl', 'http://ar2.openbms.org:8079')
        if not raw:
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
        self.client = RepublishClient(self.source_url, self._data, 
                                      restrict=self.restrict)
        self.client.connect()

        # can have multiple sources
        # RepublishClient('http://local.cs.berkeley.edu:8079', self.data).connect()

    def load(self, start_dt, end_dt, cache=True):
        """Load a range of time by pulling it from the database and
        pushing it through the operators"""
        print "starting load..."
        self.load_uids = self.operators.keys()
        self.start_dt, self.end_dt = start_dt, end_dt
        self.cache = cache
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
        #print start, end
        #print self.load_uids
        d = threads.deferToThread(self.arclient.data_uuid, 
                                  self.load_uids,
                                  start, end, 
                                  self.cache)
        d.addCallback(self.load_data)
        d.addCallback(lambda _: self._flush())
        d.addCallback(self.load_time_chunk)
        def err(e):
            print e
        d.addErrback(err)
        return d

    def load_data(self, data):
        dobj = dict((('/%s' % str(uid), {
                    'uuid' : str(uid), 
                    'Readings' : dv}) for uid, dv in zip(self.load_uids, data)))
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

def _extend(a1, a2):
    """Extend data vector a1 with vector a2"""
    assert(len(a1) == len(a2))
    rv = [None] * len(a1)
    for i in xrange(0, len(a2)):
        if len(a2[i]):
            rv[i] = np.vstack((a1[i], a2[i]))
        else:
            rv[i] = a1[i]
    return rv

def join(inputs, last=None):
    """Join together streams based on timestamps, throwing out places
    where they do not overlap"""
    times = reduce(lambda x, y: np.intersect1d(x, y[:,0]), inputs)
    vals = map(lambda x: x[np.nonzero(np.in1d(x[:,0], times)), :][0]
               if len(x) else null, inputs)
    return vals 

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
            opdata = operator(inputs[i], **state[i])
            if isinstance(opdata, np.ndarray) or \
                    isinstance(opdata, list):
                rv[i] = opdata
            else:
                rv[i], state[i] = opdata
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
        self.required_tags = set.union(*map(lambda x: x.required_tags, self.ops))
        self.optional_tags = set.union(*map(lambda x: x.optional_tags, self.ops))

        Operator.__init__(self, inputs, _inputs)

    def process(self, data):
        return reduce(lambda x, y: y(x), self.ops, data)

class StandardizeUnitsOperator(Operator):
    operator_name = 'units'
    operator_constructors = [()]
    units = {
        'Watts' : ('kW', 0.001),
        }
    name = 'standardize units'
    required_tags = set(['uuid', 'Properties/UnitofMeasure'])

    def __init__(self, inputs):
        self.factors = [1.0] * len(inputs)
        outputs = copy.deepcopy(inputs)
        for i in xrange(0, len(inputs)):
            if 'Properties/UnitofMeasure' in inputs[i] and \
                    inputs[i]['Properties/UnitofMeasure'] in self.units:
                self.factors[i] = self.units[inputs[i]['Properties/UnitofMeasure']][1]
                outputs[i]['Properties/UnitofMeasure'] = \
                    self.units[inputs[i]['Properties/UnitofMeasure']][0]
        Operator.__init__(self, inputs, outputs)

    def process(self, data):
        return map(lambda (i, x): np.dstack((x[:, 0], x[:,1] * self.factors[i]))[0],
                   enumerate(data))

class GroupbyTimeOperator(Operator):
    """Time grouping operator.  Divide time into windows, and call
    group_operator on all the data in each window; return the result.
    The group_operator must return a single reading on each output
    stream.

    chunk_length: the size of the windows time is chunked into
    chunk_delay: when we call the group operator.
    """
    name = "latest buffer operator"
    def __init__(self, inputs, 
                 group_operator,
                 chunk_length=10,
                 chunk_delay=1):
        self.bucket_op = group_operator(inputs)
        Operator.__init__(self, inputs, outputs=self.bucket_op.outputs)
        self.pending = [null] * len(self.outputs)
        self.chunk_length = chunk_length
        self.chunk_delay = chunk_delay

    def process(self, input):
        # store the new data
        # print "processing..."
        self.pending = _extend(self.pending, input)

        # apply the grouping operator to each window
        startts = min(map(lambda x: np.min(x[:, 0]) if len(x) else np.inf,
                          self.pending))
        endts = max(map(lambda x: np.max(x[:, 0]) if len(x) else 0, 
                        self.pending))
        rv = [null] * len(self.outputs)

        if startts == np.inf or endts == 0:
            return rv

        startts = int(startts - (startts % self.chunk_length))
        endts = int((endts - (endts % self.chunk_length)) - \
                        (self.chunk_length * self.chunk_delay))
 
        # iterate over the groups
        for time in xrange(startts, endts, self.chunk_length):
            # print "group starting", time
            data = map(lambda x: x[np.where((x[:,0] >= time) & 
                                            (x[:,0] < time + self.chunk_length))] 
                       if len(x) else np.array([[time, np.nan]]),
                       self.pending)
            data = [x if len(x) else np.array([[time, np.nan]]) for x in data]
            # apply
            opresult = self.bucket_op(data)
            if max(map(len, opresult)) > 1:
                raise SmapException("Error! Grouping operators can not produce "
                                    "more than one result per group!")
            rv = _extend(rv, opresult)

        # filter out the data we operated on
        self.pending = map(lambda x: x[np.nonzero(x[:, 0] >= endts)]
                           if len(x) else null, 
                           self.pending)
        return rv

class GroupByTagOperator(Operator):
    def __init__(self, inputs, group_operator, group_tag):
        groups = [None]
        self.group_idx = [[]]
        group_inputs = [[]]
        # compute 
        for i, s in enumerate(inputs):
            if not s.get(group_tag, None) in groups:
                groups.append(s[group_tag])
                self.group_idx.append(list())
                group_inputs.append(list())

            g_idx = groups.index(s.get(group_tag, None))
            group_inputs[g_idx].append(s)
            self.group_idx[g_idx].append(i)


        self.operators = [group_operator(x) if len(x) else PrintOperator([])
                          for x in group_inputs]

        Operator.__init__(self, inputs, 
                          outputs=util.flatten(map(operator.attrgetter('outputs'), 
                                                   self.operators)))

    def process(self, data):
        rv = [[] for x in xrange(0, len(self.operators))]
        for i, op in enumerate(self.operators):
            input_data = [data[j] for j in self.group_idx[i]]
            rv[i] = self.operators[i](input_data)
        return util.flatten(rv)

class BufferedJoinOperator(Operator):
    """This operator takes an arbitrary number of streams as input,
    and combines them by joining on timestamp.  It keeps a
    variable-size join buffer in case readings come at different
    rates.
    """
    name = "buffered join"
    maxbufsz = 100
    joinmethod = staticmethod(join)

    def __init__(self, inputs):
        Operator.__init__(self, inputs, outputs=OP_N_TO_N)
        self.pending = [null] * len(inputs)
        self.last = -1

    def process(self, input):
        # add new data to the pending map
        self.pending = map(lambda (x, y): np.vstack((x,y)),
                           zip(self.pending, input))
        # find what data we can deliver
        output = self.joinmethod(self.pending, last=self.last)
        # and filter out data we no longer need
        if len(output[0]):
            self.last = np.max(output[0][:, 0])
            self.pending = map(lambda x: x[np.nonzero(x[:, 0] > self.last)],
                               self.pending)
        # truncate buffer
        self.pending = map(lambda x: x[-self.maxbufsz:], self.pending)
        return output


class _MissingDataOperator(Operator):
    """For row-wise aligned input data, only yield rows where more
    than ndatathresh percent of the streams have data (that is, are
    not nan).

    inputs: equal-length vectors with missing data represented by nan
    outputs: the same data, but only where sufficient streams have data
    """
    name = 'missing filter'
    def __init__(self, inputs, ndatathresh=0.6):
        Operator.__init__(self, inputs, OP_N_TO_N)
        self.ndatathresh = ndatathresh

    def process(self, inputs):
        # the sum of anything and a nan is nan
        times = np.vstack(map(lambda x: x[:, 1], inputs))
        nancnt = np.sum(np.isnan(times), axis=0)
        takerows = np.where(len(inputs) - nancnt >= len(inputs) * self.ndatathresh)
        if len(takerows[0]):
            return map(lambda x: x[takerows], inputs)
        else:
            return [null] * len(inputs)


def _subsample(vec, last=-1, bucketsz=5):
    if len(vec) == 0:
        return null, {'last' : last,
                      'bucketsz' : bucketsz}
    
    # ignore data before "last"
    vec[:, 0] -= np.mod(vec[:,0], bucketsz)
    times = vec[:,0]
    sp = np.where(times > last)
    if len(sp[0]) == 0: 
        return null, {'last': last,
                      'bucketsz': bucketsz}
    else: sp = sp[0][0]

    # add a dummy "last" ts
    times = np.hstack(([last], times[sp:]))
    # and bucket the times
    # we want the first point in each bucket
    takes = np.nonzero(times[1:] - times[:-1])
    rv = vec[takes[0] + sp]
    rv[:,0] = times[takes[0] + 1]
    return rv, {'last': np.max(rv[:,0]), 
                'bucketsz' : bucketsz}

class SubsampleOperator(ParallelSimpleOperator):
    """Subsample N streams in parallel by taking the first reading
    that comes in within each bucket.
    """
    # the operator we'll parallelize across all input streams
    base_operator = staticmethod(_subsample)
    def __init__(self, inputs, windowsz):
        self.name = 'subsample-%i' % windowsz
        ParallelSimpleOperator.__init__(self, inputs, 
                                        bucketsz=windowsz)

def _snaptimes(vec, bucketsz=300):
    vec[:,0] -= np.mod(vec[:,0], bucketsz)
    return vec

class SnapTimes(ParallelSimpleOperator):
    base_operator = staticmethod(_snaptimes)
    def __init__(self, inputs, windowsz):
        self.name = 'snaptimes-%i' % windowsz
        ParallelSimpleOperator.__init__(self, inputs,
                                        bucketsz=windowsz)


class PrintOperator(Operator):
    """N-N operator which prints all the input data
    """
    name = "print"
    def __init__(self, inputs):
        # don't change uuids
        Operator.__init__(self, inputs, inputs)

    def process(self, inputs):
        print inputs
        return inputs

class StripMetadata(Operator):
    name = "strip_metadata"
    operator_name = 'strip_metadata'
    operator_constructors = [()]

    def __init__(self, inputs):
        outputs = [{} for x in xrange(0, len(inputs))]
        for i, stream in enumerate(inputs):
            for k, v in stream.iteritems():
                if not k.startswith('Metadata/'):
                    outputs[i][k] = v
        Operator.__init__(self, inputs, outputs)

    def process(self, inputs):
        return inputs

class DatetimeOperator(ParallelSimpleOperator):
    required_tags = set(['uuid', 'Properties/Timezone'])
    name = 'datetime'

    def __init__(self, inputs):
        tz = set(map(operator.itemgetter('Properties/Timezone'), inputs))
        if len(tz) != 1:
            raise SmapException("Datetime operator only supports a single tz")
        self.tz = gettz(list(tz)[0])
        self.base_operator = lambda vec: self._base_operator(vec)
        ParallelSimpleOperator.__init__(self, inputs)

    def _base_operator(self, vec):
        return zip(map(lambda x: dtutil.ts2dt(x).astimezone(self.tz), 
                       map(int, vec[:,0].astype(np.int))), vec[:, 1])


if __name__ == '__main__':
    from smap.drivers.sumr import SubtractOperator
    c = SmapClient()
    q = 'Metadata/Extra/Type = "room temperature" or Metadata/Extra/Type = "room setpoint"'
    inputs = c.tags(q)
    op = GroupByTagOperator(inputs, lambda x: SubtractOperator(x, 'Metadata/Extra/Type', 300000), 'Metadata/Extra/Vav')

    data = c.latest(q, streamlimit=1000, limit = 500)
    data = [np.array(x['Readings']) for x in data]
    print op(data)
