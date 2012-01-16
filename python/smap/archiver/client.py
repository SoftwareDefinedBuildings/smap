
import sys
import urllib2
import urllib
import json
import operator
import pprint
import time
from StringIO import StringIO

import numpy as np
import smap.util as util
import tscache
from smap.core import SmapException

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

class SmapClient:
    """Blocking client class for the archiver API.
    """
    def __init__(self, base='http://new.openbms.org/backend', key=None, private=False, timeout=5.0):
        self.base = base
        self.timeout = timeout
        self.key = key
        self.private = private

    def _build_qdict(self):
        """return a query dict to be passed with all requests"""
        rv = {}
        if self.key:
            rv['key'] = self.key
        if self.private:
            rv['private'] = ''
        return rv

    def query(self, q):
        """Send a query using the ARD query language to the server, and return
the result.

:param str q: the query
:return: the parsed JSON object returned by the server
"""
        try:
            fp = urllib2.urlopen(self.base + '/api/query?' + 
                                 urllib.urlencode(self._build_qdict()),
                                 data=q, 
                                 timeout=self.timeout)
            rv = json.load(fp)
        except urllib2.HTTPError:
            log.err("Bad request running query: ""%s"" " % q)
            raise SmapException()
        fp.close()
        return rv

    def tags(self, qbody, tags='*', nest=False):
        """Look up tags associated with a specific query body"""
        tags = self.query('select %s where %s' % (tags, qbody))
        if not nest:
            return map(lambda t: dict(util.buildkv('', t)), tags)
        else:
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
        
    def data_uuid(self, uuids, start, end, cache=True):
        """Load a time range of data for a list of uuids
        
        Attempts to use cached data and load missing data in parallel.

:param list uuids: a list of stringified UUIDs
:param int start: the timestamp of the first record in seconds, inclusive
:param int end: the timestamp of the last record, exclusive
:return: a list of data vectors.  Each element is
  :py:class:`numpy.array` of data in the same order as the input list of
  uuids
        """
        qdict = self._build_qdict()
        qdict['limit'] = -1
        data, urls = {}, []
        start, end = start * 1000, end * 1000
        now = int((time.time() - 300) * 1000)

        # construct a list of all holes in the cache
        for u in uuids:
            data[u] = self._data_uuid(u, start, end, cache)

            # these are the regions of missing data
            for region in data[u][0]:
                qdict['starttime'] = str(region[0][0])
                qdict['endtime'] = str(region[0][1])
                dlurl = str(self.base + '/api/data/uuid/' + u + '?' +
                            urllib.urlencode(qdict))
                if qdict['starttime'] != qdict['endtime']:
                    region.append(dlurl)
                    urls.append(dlurl)
                else:
                    region.append(None)

        # load all of the missing chunks in parallel
        newdata = dict(get(urls))

        # insert all the new data and return the result
        rv = []
        for u in uuids:
            loaddata = []
            for range, url in data[u][0]:
                if url != None and len(newdata[url][0]['Readings']) > 0:
                    assert newdata[url][0]['uuid'] == u
                    loaddata.append(np.array(newdata[url][0]['Readings']))
                    print "downloaded", len(loaddata[-1])

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

    def data(self, qbody, start, end):
        """Load data for streams matching a particular query"""
        uids = self.query('select distinct uuid where %s' % qbody)
        data = self.data_uuid(uids, start, end)
        return uids, data

    def prev(self, qbody, ref, limit=1):
        return self._data(qbody, 'prev', 
                          starttime=str(start*1000),
                          limit=str(limit))

    def next(self, qbody, ref, limit=1):
        return self._data(qbody, 'next', 
                          starttime=str(start*1000),
                          limit=str(limit))

    def latest(self, qbody, limit=1):
        return self._data(qbody, 'prev', 
                          starttime=str(0xffffffff*1000),
                          limit=str(limit))


class RepublishClient:
    """Listener for streaming data from a sMAP source or archiver's /republish feed
    """
    def __init__(self, url, datacb, reconnect=True, restrict=None):
        """
:param str url: url of the source
:param datacb: callable to be called with each new sMAP object
:param bool reconnect: weather to reconnect if the socket connection is dropped.
        """
        self.url = url
        self.datacb = datacb
        self.agent = Agent(reactor)
        self.reconnect = reconnect
        self.failcount = 0
        self.restrict = restrict

    class DataReceiver(LineReceiver):
        """Make our own LineReceiver to read back the streaming data
        from the server.  Use the right delimiter and make sure we can
        handle big objects."""
        MAX_LENGTH = 1e7
        delimiter = '\n\n'

        def __init__(self, client):
            self.client = client

        def lineReceived(self, line):
            self.failcount = 0
            try:
                obj = util.json_decode(line)
                self.client.datacb(obj)
            except:
                log.err()
                print line

        def connectionLost(self, reason):
            self.client.failed()
            self.client._reconnect()

    def failed(self):
        if self.failcount < 5:
            self.failcount += 1

    def __request(self, response):
        receiver = RepublishClient.DataReceiver(self)
        receiver.setLineMode()
        response.deliverBody(receiver)

    def _reconnect(self):
        """Exponential backup on the reconnect policy"""
        if self.reconnect:
            print "connection failed, reconnecting in", (self.failcount ** 2)
            reactor.callLater(self.failcount ** 2, self.connect)

    def _connect_failed(self, reason):
        self.failed()
        self._reconnect()

    def connect(self):
        if not self.restrict:
            d = self.agent.request('GET',
                                   self.url + '/republish',
                                   Headers(),
                                   None)
        else:
            d = self.agent.request('POST',
                                   self.url + '/republish',
                                   Headers(),
                                   FileBodyProducer(StringIO(self.restrict)))
        d.addCallback(self.__request)
        d.addErrback(self._connect_failed)

# if __name__ == '__main__':
#     def cb(line):
#         print line
#         pass

#     c = RepublishClient('http://smote.cs.berkeley.edu:8079', cb,
#                         restrict="Metadata/SourceName ~ '^410'")
#     c.connect()
#     reactor.run()


if __name__ == '__main__':
    import time
    # c = SmapClient('http://new.openbms.org/backend')
    # c = SmapClient('http://local.cs.berkeley.edu:8079')
    c = SmapClient('http://localhost:8079')
#     print c.tags('Metadata/SourceName = "410 Labjacks"')
#     print c.latest('Metadata/SourceName = "Cory Hall Dent Meters"', limit=1)
    #c._data_uuid('018eba5e-51b6-5a8d-920f-b5a831546610', 
    #             int(time.time()) - 3600 * 24, int(time.time()))
    data = c.data_uuid(['018eba5e-51b6-5a8d-920f-b5a831546610'], 
                       int(time.time()) - 3600 * 300, int(time.time()))
    
    # print data
    print len(np.unique(data[0][:,0])), len(data[0][:,0])
