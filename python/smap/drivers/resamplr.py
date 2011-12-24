
import uuid
import shelve
import time
import urllib
import pprint
import traceback

from twisted.internet import reactor, threads
import numpy as np

import smap.driver as driver
import smap.util as util
import smap.smapconf as smapconf
from smap.contrib import dtutil
from smap.archiver.client import RepublishClient, SmapClient
from twisted.web.client import getPage

class Operator:
    # data type of operator output
    data_type = ('double', float)

    def __init__(self, inputs):
        """
        :param inputs: list of uuids the operator examines
        """
        self.inputs = inputs

    def _uuid(self):
        """Return the UUID for the substream"""
        return uuid.uuid5(uuid.UUID(self.inputs[0]), self.name)

    def _name(self):
        """Return a stringified name for the operator"""
        raise NotImplementedError()

    uuid = property(_uuid)
    name = property(_name)

    def reset(self):
        """Reset the internal state to discard any changes made"""
        raise NotImplementedError()

    def bulk(self, recs):
        """Process a number of records in bulk

:param list recs: a list of (timestamp, value) tuples
:return list: a list of (timestamp, value)  """
        raise NotImplementedError()


class SubsampleOperator(Operator):
    """An operator which returns the first record in a window.
    """
    def __init__(self, input, period):
        Operator.__init__(self, [input])
        self.period = period
        self.reset()

    def _name(self):
        """Human-readable name for the operator"""
        return 'subsample-%i' % self.period
    name = property(_name)

    def reset(self):
        """Reset the internal state"""
        self.last = 0

    def __str__(self):
        return "subsample period: %i last: %s" % (self.period, 
                                                  time.ctime(self.last))

    def bulk(self, recs):
        tic = time.time()
        rv = []
        for rec in recs:
            newts = rec[0] - (rec[0] % (self.period))
            if newts > self.last:
                rv.append((newts, float(rec[1])))
                self.last = newts
        # print "in: %i out: %i (%0.3f)" % (len(recs), len(rv), (time.time() - tic))
        return rv

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
    def add_operator(self, path, op, unit):
        """Add an operator to the driver
        """
        self.add_timeseries(path, op.uuid, unit, 
                            data_type=op.data_type[0],
                            milliseconds=False)
        self.set_metadata(path, {
                'Extra/SourceStream' : str(op.inputs[0]),
                'Extra/Operator' : str(op.name)
                })

        for source in op.inputs:
            if not source in self.operators:
                self.operators[source] = {}
            if not op.uuid in self.operators[source]:
                self.operators[source][op.uuid] = (path, op)

    def reset(self):
        """Reset all operators"""
        for oplist in self.operators.itervalues():
            for path, op in oplist.itervalues():
                op.reset()

    def _data(self, data):
        """Process incoming data by pushing it through the operators
        """
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
                new = op.bulk(data)
                for newv in new:
                    ts, v = int(newv[0]), op.data_type[1](newv[1])
                    self._add(addpath, ts, v)

    def setup(self, opts, shelveoperators=True, cache=False):
        self.source_url = opts.get('SourceUrl', 'http://smote.cs.berkeley.edu:8079')
        if shelveoperators:
            self.operators = shelve.open(opts.get('OperatorCache', '.operators'),
                                         protocol=2, writeback=True)
            # sync the operator state periodically and at exit
            util.periodicCallInThread(self.operators.sync).start(60)
            reactor.addSystemEventTrigger('after', 'shutdown', 
                                          self.operators.close)
        else:
            self.operators = {}
        self.arclient = SmapClient(self.source_url)
        self.cache = cache

        # create timeseries from cached operator state
        for sid, oplist in self.operators.iteritems():
            for path, op in oplist.itervalues():
                self.add_operator(path, op, '')

    def start(self):
        """Start receiving real-time data when used in daemon mode"""
        # set up clients to provide the data
        self.client = RepublishClient(self.source_url, self._data)
        self.client.connect()

        # can have multiple sources
        # RepublishClient('http://local.cs.berkeley.edu:8079', self.data).connect()

    def load(self, start_dt, end_dt):
        """Load a range of time by pulling it from the database and
        pushing it through the operators"""
        print "starting load..."
        self.load_uids = self.operators.keys()
        self.start, self.end  = dtutil.dt2ts(start_dt), \
            dtutil.dt2ts(end_dt)

        if len(self.load_uids) > 0:
            return self.load_next_uid()
        else:
            return None

    def load_next_uid(self):
        if len(self.load_uids):
            self.current_uid = self.load_uids.pop()
            print self.current_uid
            return self.load_next_time()

    def load_next_time(self):
        d = threads.deferToThread(self.arclient.data_uuid, [self.current_uid], 
                                  self.start, self.end, self.cache)
        d.addCallback(self.load_data)
        d.addErrback(lambda x: self.load_next_uid())
        return d

    def load_data(self, data):
        self._data({'/%s' % str(self.current_uid) : {
                    'uuid': self.current_uid,
                    'Readings': data[0]}})
        return self.load_next_uid()

class SubsampleDriver(OperatorDriver):
    def setup(self, opts):
        """Set up what streams are to be subsampled.

        We'll only find new streams on a restart ATM.
        """
        OperatorDriver.setup(self, opts)
        self.restrict = opts.get("Restrict", 
                                 "has Path and (not has Metadata/Extra/SourceStream)")
        client = SmapClient(smapconf.BACKEND)
        source_ids = client.tags(self.restrict, 'distinct uuid')
        for new in source_ids:
            id = str(new[''])
            if not id in self.operators:
                o1 = SubsampleOperator(id, 300)
                self.add_operator('/%s/%s' % (id, o1.name), o1, '')
                o2 = SubsampleOperator(id, 3600)
                self.add_operator('/%s/%s' % (id, o2.name), o2, '')
