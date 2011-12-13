
import uuid
import shelve
import time
import urllib
import pprint

from twisted.internet import reactor

import smap.driver as driver
import smap.util as util
import smap.smapconf as smapconf
from smap.archiver.client import RepublishClient, SmapClient
from twisted.web.client import getPage

class Operator:
    # int minwindow: the minimum number of records which must be present to process
    minwindow = 1
    # int maxwindow: the maximum number of records we can handle at once
    maxwindow = 10000
    #
    timeout = None

    data_type = 'double'

    # timestamp of the last piece of data we looked at
    last = 0

    def __init__(self):
        self.__data = []
        self.state = {}

    def bulk(self, recs):
        """Process a number of records in bulk

:param list recs: a list of (timestamp, value) tuples
:return list: a list of (timestamp, value)  """
    
    def push(self, streamid, val):
        """Push a new reading to the operator"""
        if not streamid in self.__data:
            self.__data[streamid] = []
        self.__data[streamid].append(val)
        if len(self.__data[streamid]) > self.minwindow:
            self.bulk(self.__data[streamid])


class SubsampleOperator(Operator):
    def name(self):
        return 'subsample-%i' % self.period

    def __init__(self, period):
        Operator.__init__(self)
        self.period = period
        self.last = 0

    def __str__(self):
        return "subsample period: %i last: %s" % (self.period, 
                                                  time.ctime(self.last / 1000))

    def bulk(self, recs):
        tic = time.time()
        rv = []
        for rec in recs:
            newts = rec[0] - (rec[0] % (self.period * 1000))
            if newts > self.last:
                rv.append((newts, float(rec[1])))
                self.last = newts
        print "in: %i out: %i (%0.3f)" % (len(recs), len(rv), (time.time() - tic))
        return rv

class OperatorDriver(driver.SmapDriver):
    # a list of operators the driver will compute.  Each list element
    # is the constructor for an operator which will create a new
    oplist = [lambda: SubsampleOperator(300), lambda: SubsampleOperator(3600)]

    # chunksize for reading with loading
    limit = 50000

    def data(self, data):
        """Process incoming data by pushing it through the operators
        """
        for v in data.itervalues():
            source_id = str(v['uuid'])

            # create new operators if this is a new uuid
            if not source_id in self.operators:
                self.operators[source_id] = []
                for op in self.oplist:
                    newop = op()
                    # operator uuids use the parent stream as a
                    # namespace, and the operator name as a hash.
                    id = uuid.uuid5(uuid.UUID(v['uuid']), newop.name())
                    path = '/' + str(v['uuid']) + '/' + newop.name()
                    self.add_timeseries(path, id, '', 
                                        data_type=newop.data_type,
                                        milliseconds=True)
                    self.operators[source_id] = self.operators[source_id] + \
                        [(path, id, str(v['uuid']), newop)]
                    self.set_metadata(path, {
                            'Extra/SourceStream' : str(v['uuid']),
                            'Extra/Operator' : newop.name()
                            })

            for _,__,___,o in self.operators[source_id]:
                new = o.bulk(v['Readings'])
                addpath = "/" + str(v['uuid']) + '/' + o.name()
                for newv in new:
                    self.add(addpath, *newv)

    def setup(self, opts):
        self.source_url = opts.get('SourceUrl', 'http://smote.cs.berkeley.edu:8079')
        self.operators = shelve.open(opts.get('OperatorCache', '.operators'),
                                     protocol=2, writeback=True)
        self.restrict = opts.get("Restrict", "has Path and not has Metadata/Extra/SourceStream")
        self.lastmap = {}
        # create timeseries from cached operator state
        for oplist in self.operators.itervalues():
            for path, id, sid, op in oplist:
                self.add_timeseries(path, id, '', 
                                    data_type=op.data_type,
                                    milliseconds=True)
                self.set_metadata(path, {
                        'Extra/SourceStream' : sid,
                        'Extra/Operator' : op.name()
                        })
                lst = self.lastmap.get(sid, [])
                lst.append(op.last)
                self.lastmap[sid] = lst

        util.periodicCallInThread(self.operators.sync).start(60)
        reactor.addSystemEventTrigger('after', 'shutdown', 
                                      self.operators.close)

    def start(self):
        """Start receiving real-time data when used in daemon mode"""
        # set up clients to provide the data
        self.client = RepublishClient(self.source_url, self.data)
        self.client.connect()

        # can have multiple sources
        RepublishClient('http://local.cs.berkeley.edu:8079', self.data).connect()

        # sync the operator state periodically and at exit

    def load(self, start_dt, end_dt):
        """Load a range of time by pulling it from the database and
        pushing it through the operators"""
        self.client = SmapClient(smapconf.BACKEND)
        self.load_uids = self.client.query("select distinct uuid where %s" % self.restrict)
        d = self._flush()
        d.addCallbacks(lambda x: self._flush())

        if len(self.load_uids) > 0:
            return self.load_next_uid()
        else:
            return None

    def load_next_uid(self):
        self.current_uid = self.load_uids.pop()
        self.current_starttime = min(self.lastmap.get(self.current_uid, [0])) / 1000
        print time.ctime(self.current_starttime)
        return self.load_next_time()

    def load_next_time(self):
        now = int(time.time())
        d = getPage(smapconf.BACKEND + \
                        ("/api/data/uuid/%s?" % str(self.current_uid)) +\
                        urllib.urlencode({'starttime' : (self.current_starttime * 1000),
                                          'endtime' : now * 1000,
                                          'limit' : self.limit}))
        d.addCallback(self.load_data)
        d.addErrback(lambda x: self.load_next_time())
        return d

    def load_data(self, data):
        obj = util.json_decode(data)
        self.data({'/%s' % str(self.current_uid) : obj[0]})
        if len(obj[0]["Readings"]) == self.limit:
            self.current_starttime = (obj[0]["Readings"][-1][0] / 1000)
            print "new starttime", time.ctime(self.current_starttime)
            return self.load_next_time()
        else:
            return self.load_next_uid()
