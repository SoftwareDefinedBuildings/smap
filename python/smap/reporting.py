
import os
import sys
import time
import traceback

import util
import json
import copy
import pprint
import cStringIO as StringIO

from twisted.internet import reactor, task, defer, threads
from twisted.web.client import Agent
from twisted.web.http_headers import Headers
from twisted.python import log
import logging

import core
import disklog
from contrib import client

# this is the largest number of records we will store.
BUFSIZE_LIMIT = 100000

# the most records to pack into a single log entry/message to the server
REPORT_RECORD_LIMIT = 10000

def reporting_copy(obj):
    if isinstance(obj, dict):
        rv = dict(obj)
        for k in rv.keys():
            rv[k] = reporting_copy(rv[k])
        return rv
    elif isinstance(obj, list):
        rv = list(obj)
        for i in xrange(0, len(rv)):
            rv[i] = reporting_copy(rv[i])
        return rv
    else:
        return obj

"""Iterate over all the colletions and timeseries contained in a
report object.
"""
def reporting_map(rpt, col_cb, ts_cb):
    q = ['/']
    while len(q) > 0:
        cur_path = util.norm_path(q.pop(0))
        cur = rpt.get(cur_path, None)
        if not cur: continue
        if 'Contents' in cur:
            for pc in cur['Contents']:
                q.append(cur_path + '/' + pc)
            col_cb(cur_path, cur)
        else:
            ts_cb(cur_path, cur)
        del rpt[cur_path]

    for p, v in rpt.iteritems():
        if 'Contents' in v:
            col_cb(p, v)
        else:
            ts_cb(p, v)

"""Push all metadata down to the leaves and remove the collections
"""

def push_metadata(rpt):
    for k, v in rpt.iteritems():
        sp = util.split_path(k)
        if 'Readings' in v:
            for i in xrange(0, len(sp)):
                if util.join_path(sp[:i]) in rpt:
                    upobj = rpt[util.join_path(sp[:i])]
                    if 'Contents' in upobj:
                        del upobj['Contents']
                    v.update(util.dict_merge(upobj, v))
    for k, v in rpt.items():
        if not 'Readings' in v:
            del rpt[k]

class DataBuffer:
    """Buffer outgoing data.

    This buffer class allows you to add readings which are stored into
    a circular buffer.  It supports split-phase adding and delivery by
    returning a "truncation specification" along with the data so that
    if you later wish to shorten the buffer to remove previously read
    data, you can do that.  Note that since this is a circular buffer,
    that may mean removing less data than you read back (some may have
    been overwritten).
    """
    def __init__(self, datadir):
        """
        :param int max_size: the maximum total log size, in records
        """
        log.msg("Create databuffer " + datadir)
        self.datadir = datadir
        self.data = disklog.DiskLog(datadir)
        self.head_metric = self.metric(self.data.tail())
        # if we do a read, we have to add a new log record so we don't
        # keep appending to the same one
        self.clear = False

    def __str__(self):
        return "DataBuffer len: %i" % len(self.data)

    def __len__(self):
        return len(self.data)

    def sync(self):
        self.data.sync()

    def metric(self, val):
        if hasattr(val, '__iter__'):
            if 'Readings' in val:
                val_metric = len(val['Readings'])
            else: val_metric = len(val)
        else:
            val_metric = 1
        return val_metric

    def add(self, key, val):
        """Enqueue a new object for delivery with a subscription

        :param string key: The key for the data stream
        :param string val: The new value for the object.  Copied.
        """
        tail = self.data.tail()

        # length of the head
        val_metric = self.metric(val)

        if tail == None or self.clear:
            self.data.append({key: reporting_copy(val)})
            self.head_metric = val_metric
            self.clear = False
        elif 'Contents' in val and len(val['Contents']) == 0:
            # okay to skip b/c it doesn't apply to anything
            pass
        elif key in tail and len(val) == 2 and \
                'Readings' in val and 'uuid' in val:
            if not 'Readings' in tail[key]:
                tail[key]['Readings'] = []
            if self.head_metric < REPORT_RECORD_LIMIT:
                tail[key]['Readings'].extend(val['Readings'])
                self.data.update_tail(tail)
                self.head_metric += val_metric
            else:
                self.data.append({key: reporting_copy(val)})
                self.head_metric = val_metric

        # really this might just want to merge updates...
        elif key in tail and val == tail[key]:
            pass
        elif not key in tail and self.head_metric < REPORT_RECORD_LIMIT:
            tail[key] = reporting_copy(val)
            self.data.update_tail(tail)
            self.head_metric += val_metric
        else:
            self.data.append({key: reporting_copy(val)})
            self.head_metric = val_metric

    def truncate(self):
        """Truncate a set of readings based on the sequence number
        stored from a previous read"""
        self.data.pop()
        
    def read(self):
        """Read n points (per stream) back as a flat list.  AlsoFi
        return a truncation specification so we can remove this data
        later if desired

        :rvalue: readings, tspec.  ``readings`` is the reading object
        you can send to a consumer.  ``tspec`` can be passed to
        ``truncate()`` and will removme exactly the data you just read
        -- note this is necessary because the log is a circular buffer
        and may have wrapped while you were processing the readings.
        """
        if len(self.data) > 0:
            self.clear = True
            return self.data.head()
        else:
            raise core.SmapException("No Pending Data!")


class ReportInstance(dict):
    """Represent the stored state pending for one report destination
    """
    def __init__(self, datadir, *args):
        dict.__init__(self, *args)
        if not 'MinPeriod' in self:
            self['MinPeriod'] = 0
        if not 'MaxPeriod' in self:
            self['MaxPeriod'] = 2 ** 31 - 1
        self['DataDir'] = datadir
        self['PendingData'] = DataBuffer(datadir)
        self['ReportDeliveryIdx'] = 0
        self['LastAttempt'] = 0
        self['LastSuccess'] = 0
        self['Busy'] = False

    def deliverable(self):
        """Check if attempt should be called
        :rvalue boolean: True if a report should be sent
        """
        now = util.now()
        return (now - self['LastSuccess'] > self['MaxPeriod']) or \
            (len(self['PendingData']) > 0 and \
                 (now - self['LastSuccess']) > self['MinPeriod'])

    def attempt(self):
        """Try to make a delivery
        :rvalue: a :py:class:`Deferred` of the attempt
        """
        if 'Busy' in self and self['Busy']:
            return

        try:
            data = self['PendingData'].read()
            if data == None:
                self['PendingData'].truncate()
                return
        except Exception, e:
            print e
            return

        self['LastAttempt'] = util.now()
        log.msg("publishing to %s: %i %s" % 
                (self['ReportDeliveryLocation'][self['ReportDeliveryIdx']],
                 len(data), 
                 str([len(x['Readings']) 
                      for x in data.itervalues() 
                      if 'Readings' in x])),
                logLevel=logging.DEBUG)
        # set up an agent to push the data to the consumer
        agent = Agent(reactor)
        try:
            v = StringIO.StringIO()
            util.dump_json(data, v)
            v.seek(0)
            d = agent.request('POST',
                              str(self['ReportDeliveryLocation'][self['ReportDeliveryIdx']]),
                              Headers({'Content-type' : 
                                       ['application/json']}),
                              client.FileBodyProducer(v))
        except:
            traceback.print_exc()
            return

        def makeSuccessCb():
            # make a closure for removing the delivered data
            # on a success
            def cbResponse(resp):
                self['Busy'] = False
                if resp.code in [200, 201, 204]:
                    # on success record the time and remove the data
                    self['LastSuccess'] = util.now()
                    self['PendingData'].truncate()
                    if len(self['PendingData']) > 0:
                        # this causes a new deferred to get added to
                        # the chain, so we continue immediately at the
                        # next log position if this one worked.
                        return self.attempt()
                    else:
                        return resp
                else:
                    # but most HTTP codes indicate a failure
                    log.err("Report delivery to %s returned %i" % (
                            self['ReportDeliveryLocation'][self['ReportDeliveryIdx']],
                            resp.code))
                    self['ReportDeliveryIdx'] = ((self['ReportDeliveryIdx'] + 1) %
                                                 len(self['ReportDeliveryLocation']))
                    raise core.SmapException("Report delivery to " +
                                             str(self['ReportDeliveryLocation']) +
                                             ' returned ' + str(resp.code))
            return cbResponse

        def makeDoneCb(inst):
            inst_ = inst
            def doneCb(resp):
                inst_['Busy'] = False
                self['ReportDeliveryIdx'] = ((self['ReportDeliveryIdx'] + 1) %
                                             len(self['ReportDeliveryLocation']))
                return resp
            return doneCb

        self['Busy'] = True
        d.addErrback(makeDoneCb(self))
        d.addCallback(makeSuccessCb())
        return d


class Reporting:
    def __init__(self, inst, autoflush=1.0, reportfile=None, max_size=BUFSIZE_LIMIT):
        """Create a new report manager, responsible for delivering
        data to subscribers.  Buffers data on disk until it can be
        delivered, storing up to *max_size* points per timeseries.

        :param inst: the :py:class:`~smap.core.SmapInstance` we'll be
         delivering reports for.
        :param float autoflush: how often to call flush, which attempts
         to deliver all data.
        :param string reportfile: backing store for reporting instances
         and data which hasn't been delivered yet.
        :param int max_size: the maximum number of points we will buffer for 
         any stream.
        """
        self.inst = inst
        self.subscribers = []
        self.reportfile = reportfile
        self.max_size = max_size
        self.autoflush = autoflush
        if self.reportfile:
            self.load_reports()

        if autoflush != None:
            # add a blank callback to the deferred to kill off any errors
            def flush():
                d = self._flush()
                if d: d.addBoth(lambda _ : None)
            self.t = task.LoopingCall(flush)
            self.t.start(autoflush)

        # add a shutdown handler so we save the final reports after exiting
        if reportfile:
            reactor.addSystemEventTrigger('after', 'shutdown', 
                                          self.save_reports)

    def get_report(self, id):
        return util.find(lambda item: item['uuid'] == id, self.subscribers)

    def add_report(self, rpt):
        dir = os.path.join(self.reportfile + '-reports',
                           str(rpt['uuid']))
        report_instance = ReportInstance(dir, rpt)
        log.msg("Creating report -- dest is %s" % str(rpt['ReportDeliveryLocation']))
        self._update_subscriptions(report_instance)
        self.subscribers.append(report_instance)

        # publish the full data set when we add a subscription so we
        # can compress from here
        for k, v in self.inst.lookup(report_instance['ReportResource']).iteritems():
            self.publish(k, v)

    def del_report(self, id):
        rpt = self.get_report(id)
        if rpt:
            log.msg("removing report " + str(id))
            del self.subscribers[self.subscribers.index(rpt)]
        return rpt

    def update_report(self, rpt):
        """Copy in fields from a new reporting object
        """
        cur = self.get_report(rpt['uuid'])
        log.msg("updating report %s: dest is now %s" % (
                str(rpt['uuid']),
                str(rpt['ReportDeliveryLocation'])))
        if cur:
            cur.update(rpt)
            self._update_subscriptions(cur)
            return True
        return False

    def _update_subscriptions(self, sub):
        result = self.inst.lookup(sub['ReportResource'])
        if isinstance(result, dict):
            sub['Topics'] = set(result.iterkeys())
        elif isinstance(result, dict) and 'uuid' in result:
            sub['Topics'] = set([getattr(result, 'path')])
        else:
            sub['Topics'] = set()

    def update_subscriptions(self):
        """Should be called whenever the set of resources changes so we can
        update the list of uuids for each subscriber."""
        map(self._update_subscriptions, self.subscribers)

    def publish(self, path, val, prepend=False):
        """Publish a new reading to the stream identified by a path.

        Not thread safe.
        """
        path = util.norm_path(path)
        for sub in self.subscribers:
            if path in sub['Topics']:
                sub['PendingData'].add(path, val)

    def load_reports(self):
        self.subscribers = util.pickle_load(self.reportfile)
        if self.subscribers == None:
            self.subscribers = []
        for s in self.subscribers:
            s['Busy'] = False

    def save_reports(self, *args):
        """Save reports while holding the filesystem lock.
        """
        util.pickle_dump(self.reportfile, self.subscribers)
        for s in self.subscribers:
            s['PendingData'].sync()

        if len(args) == 1:
            return args[0]
        else:
            return 

    def _flush(self, force=False):
        """Send out json-packed report objects to registered listeners. 
        
        :param boolean force: if True, ignore ``MinPeriod``/``MaxPeriod``.
        :rtype: a :py:class:`twisted.internet.task.DeferredList`
         instance which will fire when deliver to all subscribers has
         finished, or errBack when any fail
        """
        deferList, deleteList = [], []
        for sub in self.subscribers:
            now = util.now()
            if sub.get('ExpireTime', now) < now:
                # remove expired reports
                deleteList.append(sub['uuid'])

            # either we've gone too long without trying and so need to
            # deliver a report or else we have new data and have
            # waited for at least MinPeriod since the last report.
            elif force or sub.deliverable():
                d = defer.maybeDeferred(sub.attempt)
                # we don't need an errBack for this case since we want
                # to propagate the error and don't need to do any
                # cleanup
                deferList.append(d)

        map(self.del_report, deleteList)
        d = defer.DeferredList(deferList, fireOnOneErrback=True, consumeErrors=True)
        d.addBoth(self.save_reports)
        return d

    def flush(self):
        """Causes delivery to be attempted for all non-busy reports
        now.  Threaded version; blocks until :py:meth:`_flush` finishes.
        """
        return threads.blockingCallFromThread(reactor, self.inst._flush)

