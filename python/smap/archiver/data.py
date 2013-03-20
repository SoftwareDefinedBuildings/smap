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
import logging

import numpy as np

from twisted.internet import reactor, threads, defer
from twisted.enterprise import adbapi
from twisted.python import log
import psycopg2

import smap.reporting as reporting
import smap.util as util
import smap.sjson as json
from smap.operators import null
from smap.core import SmapException
import settings

def makeErrback(request_):
    request = request_
    def errBack(outp):
        print "ERRBACK:", outp
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
        log.msg("ReadingdbPool shutting down:", len(self.pool))
        map(settings.rdb.db_close, self.pool)

    def get(self):
        # print "connect", settings.READINGDB_HOST, settings.READINGDB_PORT
        return settings.rdb.db_open(host=settings.conf['readingdb']['host'],
                           port=settings.conf['readingdb']['port'])
            
    def put(self, conn):
        # self.pool.append(conn)
        settings.rdb.db_close(conn)

try:
    if hasattr(settings, "rdb"):
        rdb_pool
    else:
        log.err("failed to find readingdb module")
except NameError:
    rdb_pool = ReadingdbPool()

class SmapMetadata:
    def __init__(self, db):
        self.db = db    

    @defer.inlineCallbacks
    def add(self, subid, ids, obj):
        """Set the metadata for a Timeseries object
        """
        tic = time.time()
        for path, ts in obj.iteritems():
            if not util.is_string(path):
                raise Exception("Invalid path: " + path)

            tags = ["hstore('Path', %s)" % escape_string(path)]
            for name, val in util.buildkv('', ts):
                if name == 'Readings' or name == 'uuid': continue
                name, val = escape_string(name), escape_string(str(val))
                if not (util.is_string(name) and util.is_string(val)):
                    raise SmapException('Invalid metadata pair: "%s" -> "%s"' % (str(name),
                                                                                 str(val)),
                                        400)
                tags.append("hstore(%s, %s)" % (name, val))

            query = "UPDATE stream SET metadata = metadata || " + " || ".join(tags) + \
                " WHERE uuid = %s" % escape_string(ts['uuid'])

            # skip path updates if no other metadata
            if len(tags) == 1:
                continue
            yield self.db.runOperation(query)
        logging.getLogger('stats').info("Metadata insert took %0.6fs" % (time.time() - tic))


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
        divisor = settings.conf['readingdb']['divisor']
        try:
            r = rdb_pool.get()
            for ts in obj.itervalues():
                data = [(x[0] / divisor, 0, x[1]) 
                        for x in ts['Readings'] if x[0] > 0]
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
                raise Exception("Error creating RDB connection!")
        return True

    def _add_data(self, subid, ids, obj):
        """Store the data and metadata contained in a Timeseires
        """
        ids = dict(zip(map(operator.itemgetter('uuid'), obj.itervalues()), ids))
        md = SmapMetadata(self.db)
        meta_deferred = md.add(subid, ids, obj)
        data_deferred = threads.deferToThread(self._add_data_real, ids, obj)        
        d = defer.DeferredList([meta_deferred, data_deferred], 
                               fireOnOneErrback=True, consumeErrors=True)
        # propagate the original error... 
        d.addErrback(lambda x: x.value.subFailure)
        return d

    def _run_create(self, uuids, result, newresult, start=None):
        """Chain together the stream creations so we don't exceed database limits"""
        if len(uuids) > 0:
            query = "SELECT " + ','.join(uuids[:100])
            tic = time.time()
            if start: 
                logging.getLogger('stats').info("run create: %0.6fs" % (tic - start))
            d = self.db.runQuery(query)
            d.addCallback(lambda rv: self._run_create(uuids[100:],
                                                      result + newresult[0],
                                                      map(list, rv),
                                                      start=tic))
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
    """Class to manage extracting data from the readingdb and return
    it either as a numpy matix, a list, or a smap object with
    readings.
    """
    def __init__(self, ndarray=False, as_smapobj=True):
        """
:param ndarray: return the data as a numpy matrix
:param: as_smapobj: return the data as a list of sMAP objects (dicts,
     with uuid and Readings set) instead of a bare list of data.
        """
        self.ndarray = ndarray
        self.as_smapobj = as_smapobj

    def load_data(self, request, method, streamids):
        """
:param: request: a twisted http request
:param method: 'data', 'prev', or 'next'
:param streamids: a list of (uuid, streamid) tuples data is requested for.
        """
        now = int(time.time()) * 1000

        self.streamids = streamids
        ids = map(operator.itemgetter(1), streamids)
        divisor = settings.conf['readingdb']['divisor']

        # args are a bit different for different requests
        if method == 'data':
            method = settings.rdb.db_query
            args = [
                ids,
                int(request.args.get('starttime', [now - 3600 * 24 * 1000])[0]) / divisor,
                int(request.args.get('endtime', [now])[0]) / divisor
                ]
            kwargs = {
                'limit': int(request.args.get('limit', [10000000])[0])
                }
        else:
            if method == 'prev':
                method = settings.rdb.db_prev
            elif method == 'next':
                method = settings.rdb.db_next
            args = [
                ids,
                int(request.args.get('starttime', [now])[0]) / divisor
                ]
            kwargs = {
                'n': int(request.args.get('limit', [1])[0])
                }
                

        # run the request in a (twisted) thread.
        d = threads.deferToThread(method, *args, **kwargs)

        # d.addCallback(self.check_data)

        # add the data munging if requested
        if not self.ndarray or self.as_smapobj:
            d.addCallback(self.screw_data, streamids)
        return d

    def check_data(self, data):
        """Run a check to see if the the data we get back from
        readingdb is sensible."""
        for d in data:
            times = set(d[:, 0])
            assert len(times) == len(d[:, 0])
        return data

    def screw_data(self, data, streamids):
        rv = []
        for (uid, id), d in zip(streamids, data):
            if not self.ndarray:
                d[:,0] = np.int_(d[:, 0])
                d[:,0] *= settings.conf['readingdb']['divisor']
                d = d.tolist()
            if self.as_smapobj:
                rv.append({'uuid': uid,
                           'Readings': d})
            else:
                rv.append(d)
        return rv


def send_result((request, result)):
    request.write(json.dumps(result))
    request.finish()

def log_time(result, start):
    logging.getLogger('stats').info("data load took %0.6fs" % (time.time() - start))
    return result

def data_load_result(request, method, result, send=False, **loadargs):
    """Callback that can be chained onto a db query to load the data
    from the reading db.

:param request: the twisted request
:param str method: data method
:param result: the result of a previous query (usually).  list of
    (uuid, streamid) tuples.
:param bool send: write the output to the request object.  If true,
    the resulting data will be sent back to the client by calling the
    request.write method.  Otherwise you can chain your own callback
    onto this guy.
:param loadargs: additional args for the data loader (see :py:class:`DataRequester`).
:return: a deferred which will fire with the result of loading the requested data.
    """
    count = int(request.args.get('streamlimit', ['1000'])[0])
    if count == 0:
        count = len(result)

    if len(result) > 0:
        loader = DataRequester(**loadargs)
        d = loader.load_data(request, method, result[:count])
        d.addCallback(log_time, time.time())
        return d
    else:
        return defer.succeed([])

