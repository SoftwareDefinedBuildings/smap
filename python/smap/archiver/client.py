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

import sys
import urllib2
import urllib
import operator
import pprint
import time
from StringIO import StringIO

import numpy as np
import smap.util as util
from smap import util
from smap.core import SmapException
import smap.sjson as json
from smap.archiver import tscache
from smap.archiver.settings import conf

from twisted.internet import reactor
from twisted.internet.protocol import ReconnectingClientFactory
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.protocols.basic import LineReceiver
from twisted.web.client import Agent
from twisted.web.http_headers import Headers
from twisted.python import log

try:
    from twisted.web.client import FileBodyProducer
except ImportError:
    from smap.contrib.client import FileBodyProducer

try:
    from smap.iface.http.httpcurl import get
except ImportError:
    print >>sys.stderr, """Warning -- can't find httpcurl
  --> Falling back on urllib2
  --> Install pycURL for parallel data downloads"""
    from smap.iface.http.httputils import get

def parser(data):
    """Parse a response body from the server.  Since this may include
multiple lines, we need to be careful to do this right and merge the
results together."""
    rv = {}
    for line in data.split('\n'):
        if len(line.strip()) == 0: 
            continue
        line_obj = json.loads(line)

        if not isinstance(line_obj, list): 
            return data
        if len(line_obj) == 0: continue

        for v in line_obj:
            if not 'uuid' in v:
                return line_obj
            # raise SmapException("Invalid sMAP object: " + str(v))
            id = v['uuid']
            if not id in rv:
                rv[id] = v
            else:
                if 'Readings' in v and 'Readings' in rv[id]:
                    rv[id]['Readings'].extend(v['Readings'])
                    del v['Readings']
                rv[id] = util.dict_merge(rv[id], v)
    return rv.values()

def make_qdict(key, private):
    """return a query dict to be passed with all requests"""
    rv = {}
    if key:
        if isinstance(key, list):
            rv['key'] = key
        else:
            rv['key'] = [key]
    if private:
        rv['private'] = ['']
    return rv


class SmapClient:
    def __init__(self, base=conf['default backend'],
                 key=None, private=False, timeout=50.0):
        """
:param string base: URL of the base archiver
:param string key: an archiver API key to send along with requests
:param bool private: if True, only query streams owned by `key`
:param float timeout: how long to wait for results
"""
        self.base = base
        self.timeout = timeout
        self.key = key
        self.private = private

    def query(self, q):
        """Send a query using the ARD query language to the server, and return
the result.

:param str q: the query
:return: the parsed JSON object returned by the server
"""
        try:
            fp = urllib2.urlopen(self.base + '/api/query?' + 
                                 urllib.urlencode(make_qdict(self.key, self.private), 
                                                  doseq=True),
                                 data=q, 
                                 timeout=self.timeout)
            rv = parser(fp.read())
        except urllib2.HTTPError, err:
            log.err("Bad request running query: ""%s"" " % q)
            raise SmapException("Archiver query HTTP request error %s" % err.code)
        fp.close()
        return rv

    def tags(self, where, tags='*', nest=False, asdict=False):
        """Look up tags associated with a specific query body"""
        log.msg(where)
        tags = self.query('select %s where %s' % (tags, where))
        if not nest:
            tags = map(lambda t: dict(util.buildkv('', t)), tags)
        if asdict:
            tags = dict([(x['uuid'], x) for x in tags])
        return tags
        
    def _data_uuid(self, uuid, start, end, cache):
        """Construct a list of urls we need to load for a single uuid"""
        if cache:
            cache = tscache.TimeseriesCache(uuid)
            cached_data = cache.read(0, start, end) 
            cache.close()
        else:
            cached_data = []
        
        cached_data = [((0, start), None)] + \
            cached_data + \
            [((end, 0), None)]
        load_list = []
        for idx in range(0, len(cached_data) - 1):
            fetch_start, fetch_end = cached_data[idx][0][1], cached_data[idx+1][0][0]
            load_list.append([(fetch_start, fetch_end)])
        
        return load_list, map(operator.itemgetter(1), cached_data[1:-1])

    @staticmethod
    def _parser(data):
        obj = json.loads(data)
        return obj[0]['uuid'], np.array(obj[0]['Readings'])
        
    def data_uuid(self, uuids, start, end, cache=True, limit=-1):
        """Low-level interface for loading a time range of data from a list of
uuids.  Attempts to use cached data and load missing data in parallel.

:param list uuids: a list of stringified UUIDs
:param int start: the timestamp of the first record in seconds, inclusive
:param int end: the timestamp of the last record, exclusive
:param bool cache: if true, try to save/read data from an on-disk
  cache.  Sometimes useful if the same data is frequently accessed.
:return: a list of data vectors.  Each element is
  :py:class:`numpy.array` of data in the same order as the input list of
  uuids
        """
        qdict = make_qdict(self.key, self.private)
        qdict['limit'] = [str(int(limit))]
        data, urls = {}, []
        start, end = start * 1000, end * 1000
        now = int((time.time() - 300) * 1000)

        # construct a list of all holes in the cache
        for u in uuids:
            data[u] = self._data_uuid(u, start, end, cache)
            # these are the regions of missing data
            for region in data[u][0]:
                qdict['starttime'] = [str(region[0][0])]
                qdict['endtime'] = [str(region[0][1])]
                dlurl = str(self.base + '/api/data/uuid/' + u + '?' +
                            urllib.urlencode(qdict, doseq=True))
                if qdict['starttime'][0] != qdict['endtime'][0]:
                    region.append(dlurl)
                    urls.append(dlurl)
                else:
                    region.append(None)

        # load all of the missing chunks in parallel
        newdata = dict(get(urls, parser=self._parser, verbose=False))

        # insert all the new data and return the result
        rv = []
        for u in uuids:
            loaddata = []
            for range, url in data[u][0]:
                if url != None and len(newdata[url][1]) > 0:
                    assert newdata[url][0] == u
                    loaddata.append(newdata[url][1])
                    # print "downloaded", len(loaddata[-1])

                    if cache and range[0] < now:
                        c = tscache.TimeseriesCache(u)
                        c.insert(0, range[0], range[1] if range[1] < now else now, 
                                 loaddata[-1][np.nonzero(loaddata[-1][:,0] < now)])
                        c.close()
                else:
                    v = np.array([])
                    v.shape = (0, 2)
                    loaddata.append(v)

            def interleave(x, y):
                lst = [None] * (len(x) * 2 - 1)
                for idx in xrange(0, len(x)):
                    lst[idx * 2] = x[idx]
                for idx in xrange(0, len(y)):
                    lst[idx * 2 + 1] = y[idx]
                return lst
            rv.append(np.vstack(interleave(loaddata, data[u][1])))

        return rv

    def _data(self, selector, where, limit, streamlimit):
        qbody = "select data %s limit %i streamlimit %i where %s" % \
            (selector, limit, streamlimit, where)
        return self.query(qbody)
        

    def data(self, where, start, end, limit=10000, cache=True):
        """Load data for streams matching a particular query.

:param str where: the ArchiverQuery selector for finding time series
:param int start: query start time in UTC seconds (inclusive)
:param int end: query end time in UTC seconds (exclusive)
:return: a tuple of (uuids, data).  uuids is a list of uuids matching
    the selector, and data is a list numpy matrices with the data 
    corresponding to each uuid.
        """
        uids = self.query('select distinct uuid where %s' % where)
        data = self.data_uuid(uids, start, end, limit=limit, cache=cache)
        return uids, data

    def prev(self, where, ref, limit=1, streamlimit=10):
        """Load data before a reference timestamp.  For instance, to
        locate the last reading whose timestamp is less than the
        current time, you can use ``latest(where_clause, int(time.time())``.

        :param str where: a selector identifying the streams to query
        :param int ref: reference timestamp
        :param int limit: the maximum number of points to retrieve per stream
        :param int streamlimit: the maximum number of streams to query
        """
        return self._data("before %i" % (ref * 1000), where, limit, streamlimit)

    def next(self, where, ref, limit=1, streamlimit=10):
        """Load data after a reference time.

        See `prev` for args.
        """
        return self._data("after %i" % (ref * 1000), where, limit, streamlimit)

    def latest(self, where, limit=1, streamlimit=10):
        """Load the last data in a time-series.

        See `prev` for args.
        """
        return self._data("before 4294967295000", where, limit, streamlimit)


class RepublishClient:
    """Listener for streaming data from an archiver's
`/republish` feed.  This class uses :py:class:`twisted` for
event-driven programming so this is most useful for other twisted
programs.  For instance::

 from twisted.internet import reactor

 def data_callback(data):
     print data

 r = RepublishClient("http://localhost:8079/", data_callback)
 r.connect()
 reactor.callLater(5, reactor.stop)
 reactor.run()

    """
    def __init__(self, url, datacb, 
                 restrict=None, 
                 format="numpy",
                 reconnect=True, 
                 connect_error=None,
                 key=None, private=False):
        """
:param str url: url of the archiver
:param datacb: callable to be called with each new sMAP object
:param str restrict: "where" clause restricting data to be delivered.
:param str format: "numpy" or "raw", determining the arguments to the data callback.
:param bool reconnect: weather to reconnect if the socket connection is dropped.
:param connect_error: callback to be called when the archiver returns an HTTP error code.
    This is only evaluated once, when connecting.  Will be called with a 
    :py:class:`twisted.web.client.Response` object as the first argument.
:param key: keys needed to access private data
:param bool private: 
        """
        self.url = url
        self.datacb = datacb
        self.agent = Agent(reactor)
        self.reconnect = reconnect
        self.failcount = 0
        self.restrict = restrict
        self.connect_error = connect_error
        self.format = format
        self.key = key
        self.private = private

    class DataReceiver(LineReceiver):
        """Make our own LineReceiver to read back the streaming data
        from the server.  Use the right delimiter and make sure we can
        handle big objects."""
        MAX_LENGTH = 1e7
        delimiter = '\n\n'

        def __init__(self, client, format):
            if not format in ["raw", "numpy"]:
                raise ValueError("Valid formats are raw and numpy")
            self.client = client
            self.format = format

        def lineReceived(self, line):
            self.failcount = 0
            if not len(line.strip()): return
            try:
                obj = json.loads(line)
                if self.format == "raw":
                    self.client.datacb(obj)
                else:
                    uuids, data = [], []
                    for v in obj.itervalues():
                        if 'uuid' in v:
                            uuids.append(v['uuid'])
                            data.append(np.array(v['Readings']))
                    self.client.datacb(uuids, data)
            except:
                log.err()
                print line

        def connectionLost(self, reason):
            self.client._failed()
            self.client._reconnect()

    def _failed(self):
        if self.failcount < 5:
            self.failcount += 1

    def __request(self, response):
        if response.code == 200:
            receiver = RepublishClient.DataReceiver(self, self.format)
            receiver.setLineMode()
            response.deliverBody(receiver)
            self.receiver = receiver
        elif callable(self.connect_error):
            self.connect_error(response)

    def _reconnect(self):
        """Exponential backup on the reconnect policy"""
        if self.reconnect and not self.closing:
            log.msg("connection failed, reconnecting in", (self.failcount ** 2))
            reactor.callLater(self.failcount ** 2, self.connect)

    def _connect_failed(self, reason):
        self._failed()
        self._reconnect()

    def connect(self):
        """Subscribe and start receiving data.  No callbacks will be called
before this connecting.
        """
        self.closing = False
        url = self.url + '/republish?' + \
            urllib.urlencode(make_qdict(self.key, self.private), 
                             doseq=True)

        if not self.restrict:
            d = self.agent.request('GET', url, Headers(), None)
        else:
            d = self.agent.request('POST', url, Headers(), 
                                   FileBodyProducer(StringIO(str(self.restrict))))
        d.addCallback(self.__request)
        d.addErrback(self._connect_failed)
    
    def close(self):
        """Close the connection to the server, and abandon any retries.
        """
        self.closing = True
        try:
            self.receiver.transport.stopProducing()
        except:
            return False
        return True

# if __name__ == '__main__':
#     def cb(line):
#         print line
#         pass

#     c = RepublishClient('http://smote.cs.berkeley.edu:8079', cb,
#                         restrict="Metadata/SourceName ~ '^410'")
#     c.connect()
#     reactor.run()
