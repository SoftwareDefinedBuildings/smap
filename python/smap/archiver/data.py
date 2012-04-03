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

import traceback
import operator
import pprint
import time
import gc

import numpy as np

from twisted.internet import reactor, threads, defer
from twisted.enterprise import adbapi
import psycopg2

import smap.reporting as reporting
import smap.util as util
from smap.operators import null
import settings

def makeErrback(request_):
    request = request_
    def errBack(outp):
        try:
            request.setResponseCode(500)
            request.finish()
        except:
            traceback.print_exc()

def escape_string(s):
    return psycopg2.extensions.QuotedString(s).getquoted()

class ReadingdbPool:
    def __init__(self):
        self.pool = []
        reactor.addSystemEventTrigger('after', 'shutdown', 
                                      self.shutdown)

    def shutdown(self):
        print "ReadingdbPool shutting down:", len(self.pool)
        map(settings.rdb.db_close, self.pool)

    def get(self):
        print "connect", settings.READINGDB_HOST, settings.READINGDB_PORT
        return settings.rdb.db_open(host=settings.READINGDB_HOST,
                           port=int(settings.READINGDB_PORT))
            
    def put(self, conn):
        # self.pool.append(conn)
        settings.rdb.db_close(conn)

try:
    if hasattr(settings, "rdb"):
        rdb_pool
    else:
        print "failed to find readingdb module"
except NameError:
    rdb_pool = ReadingdbPool()

class SmapMetadata:
    def __init__(self, db):
        self.db = db    
    
    def _add(self, subid, ids, obj):
        try:
            return self._add_wrapped(subid, ids, obj)
        except Exception, e:
            print "exception in _add"
            traceback.print_exc()
            log.err()
            
    def _add_wrapped(self, subid, ids, obj):
        """Update the tag set for a reading vector
        """
        vals = []
        def addTag(uid, tn, tv):
            try:
                vals.append("add_tag(%i,%s,%s)" % (ids[uid],
                                                       escape_string(tn),
                                                       escape_string(tv)))
            except Exception, e:
                print ids[uid]
                print tn, tv
                print e
                raise e
        ids = dict(ids)
        for path, ts in obj.iteritems():
            addTag(ts['uuid'], 'Path', path)
            for name, val in util.buildkv('', ts):
                if name == 'Readings' or name == 'uuid': continue
                addTag(ts['uuid'], name, val)
        return vals

    def _do_metadata(self, inserts):
        """Sequentially execute the metdata updates"""
        if len(inserts) > 0:
            query = "SELECT " + \
                    ','.join(inserts[:100])
            d = self.db.runQuery(query)
            d.addCallback(lambda _: self._do_metadata(inserts[100:]))
            return d

    def add(self, subid, ids, obj):
        """Set the metadata for a Timeseries object
        """
        d = threads.deferToThread(self._add, subid, ids, obj)
        d.addCallback(self._do_metadata)
        return d

class SmapData:
    """Class to manage entering data in a readingdb instance from a
    report object.

    1. create stream id records, if they do not exist
    2. look up stream ids
    3. defer add to a thread to use blocking c api
    """
    def __init__(self, db):
        self.db = db

    def _add_data_real(self, ids, obj):
        """Send data to a readingdb backend
        """
        r = None
        try:
            r = rdb_pool.get()
            for ts in obj.itervalues():
                data = [(x[0] / 1000, 0, x[1]) for x in ts['Readings']]
                # print "add", len(data), "to", ids[ts['uuid']], data[0][0]
                while len(data) > 128:
                    settings.rdb.db_add(r, ids[ts['uuid']], data[:128])
                    del data[:128]
                if len(data) > 0:
                    settings.rdb.db_add(r, ids[ts['uuid']], data[:128])
        except:
            raise
        finally:
            if r != None:
                rdb_pool.put(r)
            else:
                traceback.print_exc()
                raise Exception("Error creating RDB connection!")
        return True

    def _add_data(self, subid, ids, obj):
        """Store the data and metadata contained in a Timeseires
        """
        ids = dict(zip(map(operator.itemgetter('uuid'), obj.itervalues()), ids))
        md = SmapMetadata(self.db)
        meta_deferred = md.add(subid, ids, obj)

        data_deferred = threads.deferToThread(self._add_data_real, ids, obj)
        
        return defer.DeferredList([meta_deferred, data_deferred], 
                                  fireOnOneErrback=True, consumeErrors=True)

    def _run_create(self, uuids, result, newresult):
        """Chain together the stream creations so we don't exceed database limits"""
        if len(uuids) > 0:
            query = "SELECT " + ','.join(uuids[:1000])
            d = self.db.runQuery(query)
            d.addCallback(lambda rv: self._run_create(uuids[1000:],
                                                      result + newresult[0],
                                                      map(list, rv)))
            return d
        else:
            return result + newresult[0]

    def _create_ids(self, subid, obj):
        """Create any missing streamids from a Timeseries object.
        This way a select will always return the right results.
        """
        uuids = []
        query = "SELECT "
        for ts in obj.itervalues():
            uuids.append("add_stream(%i, %s)" % (subid,
                                                   escape_string(ts['uuid'])))
    
        query += ','.join(uuids)
        return self._run_create(uuids, [], [[]])

    def add(self, subid, obj):
        d = self._create_ids(subid, obj)
        # d.addCallback(lambda rv: self._get_ids(subid, obj))
        d.addCallback(lambda rv: self._add_data(subid, rv, obj))

        # all the errbacks should propagate up to the request handler so we can return a 500
        return d

def del_streams(streams):
    try:
        r = rdb_pool.get()
        for sid in streams:
            settings.rdb.db_del(r, sid, 0, 0xffffffff)
    finally:
        rdb_pool.put(r)
        

class DataRequester:
    def __init__(self, ndarray=False, as_smapobj=True):
        self.ndarray = ndarray
        self.as_smapobj = as_smapobj

    def load_data(self, request, method, streamids):
        if method == 'data':
            return self.multi_load_data(request, method, streamids)
        else:
            mdr = ManualDataRequester(ndarray=self.ndarray, 
                                      as_smapobj=self.as_smapobj)
            return mdr.load_data(request, method, streamids)

    def multi_load_data(self, request, method, streamids):
        assert method == 'data'
        now = int(time.time()) * 1000
        start = int(request.args.get('starttime', [now - 3600 * 24 * 1000])[0])
        end = int(request.args.get('endtime', [now])[0])
        limit = int(request.args.get('limit', [10000])[0])

        self.streamids = streamids
        ids = map(operator.itemgetter(1), streamids)
        d = threads.deferToThread(settings.rdb.db_multiple, 
                                  ids,
                                  start / 1000,
                                  end / 1000,
                                  limit=limit)
        d.addCallback(self.check_data)
        if not self.ndarray or self.as_smapobj:
            d.addCallback(self.screw_data, streamids)
        return d

    def check_data(self, data):
        for d in data:
            times = set(d[:, 0])
            assert len(times) == len(d[:, 0])
        return data

    def screw_data(self, data, streamids):
        rv = []
        print self.ndarray, self.as_smapobj
        for (uid, id), d in zip(streamids, data):
            if not self.ndarray:
                d[:,0] = np.int_(d[:, 0])
                d[:,0] *= 1000
                d = d.tolist()
            if self.as_smapobj:
                rv.append({'uuid': uid,
                           'Readings': d})
            else:
                rv.append(d)
        return rv


class ManualDataRequester:
    """Manage loading data from a single stream from a readingdb
    backend.  Will chain deferred together to return a partial
    timeseries which contains just the uuid and the requested data.
    """
    def __init__(self, pool_size=2, ndarray=False, as_smapobj=True):
        self.pool_size = pool_size
        self.ndarray = ndarray
        self.as_smapobj = as_smapobj

    def _munge_data(self, request, data):
        """Tweak the resulting object to be a Timeseries
        """
        if data != None:
            toc = time.time()

            data = np.vstack(map(np.array, data))
            if data.shape[1] > 0:
                data[:, 0] *= 1000
                data = data[:, [0,2]] 
            else:
                data = null
            if not self.ndarray:
                data = data.tolist()

            rv = {
                'uuid': request['uuid'],
                'Readings' : data, 
                }
            print "munge", time.time() - toc
            return rv
        return None

    def _merge_results(self, returns):
        rv = [None] * len(self.uids)
        for rc, streams in returns:
            if not rc: 
                print "ERROR: streams"
                raise streams
            for data in streams:
                if self.as_smapobj:
                    rv[self.uids.index(data['uuid'])] = data
                else:
                    data['Readings'][:, 0] /= 1000
                    rv[self.uids.index(data['uuid'])] = data['Readings']
        return rv

    def load_data(self, request, method, streamids):
        """Called to kick off a load -- returns a deferred which will
        yield a (request, Timeseries) tuple when it finishes.        
        """
        self.pending = []
        self.uids = []
        for uid, streamid in streamids:
            # if these raise an exception we'll cancel all the loads
            now = int(time.time()) * 1000
            if method == 'data':
                start = int(request.args.get('starttime', [now - 3600 * 24 * 1000])[0])
            else:
                start = int(request.args.get('starttime', [now])[0])
            end = int(request.args.get('endtime', [now])[0])
            limit = int(request.args.get('limit', [-1])[0])

            self.pending.append({
                    'uuid': uid,
                    'streamid': streamid,
                    'method': method,
                    'start': start,
                    'end': end,
                    'limit': limit,
                    'request': request,
                    })
            self.uids.append(uid)

        return self.start_workers()

    def start_workers(self):
        dl = []
        for w in xrange(0, min(len(self.pending), self.pool_size)):
            dl.append(threads.deferToThread(self.worker_thread))
        d = defer.DeferredList(dl)
        d.addCallback(self._merge_results)
        return d
    
    def worker_thread(self):
        conn = rdb_pool.get()
        try:
            return self._worker_thread(conn)
        finally:
            rdb_pool.put(conn)

    def _worker_thread(self, conn):
        pending_data = []
        print "worker thread starting"
        while True:
            try:
                request = self.pending.pop()
            except IndexError:
                return pending_data
            rv = []

            if request['method'] == 'data':
                # no limit if zero
                if request['limit'] == -1:
                    request['limit'] = 1000000

                # fetch all the data for this stream
                while True:
                    data = settings.rdb.db_query(conn, request['streamid'],
                                                 request['start'] / 1000, request['end'] / 1000)
                    t2 = time.time()
                    rv.append(data) 
                    t3 = time.time()
                    request['limit'] -= min(len(data), request['limit'])
                    if len(data) < 10000 or \
                            request['limit'] <= 0: 
                        break
                    request['start'] = (data[-1][0] + 1) * 1000
                    del data

            elif request['method'] == 'next':
                if request['limit'] == -1: request['limit'] = 1
                rv = [settings.rdb.db_next(conn, request['streamid'], 
                                           request['start'] / 1000, n = request['limit'])]
            elif request['method'] == 'prev':
                if request['limit'] == -1: request['limit'] = 1
                rv = [settings.rdb.db_prev(conn, request['streamid'], 
                                           request['start'] / 1000, n = request['limit'])]
            pending_data.append(self._munge_data(request, rv))

def send_result((request, result)):
    request.write(util.json_encode(result))
    request.finish()

def data_load_result(request, method, result, send=False, **loadargs):
    count = int(request.args.get('streamlimit', ['10'])[0])
    if count == 0:
        count = len(result)

    if len(result) > 0:
        loader = DataRequester(**loadargs)
        d = loader.load_data(request, method, result[:count])
        d.addCallback(lambda x: (request, x))
        if send: d.addCallback(send_result)
        return d
    else:
        return defer.succeed((request, []))

