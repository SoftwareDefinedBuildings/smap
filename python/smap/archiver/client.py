
import sys
import urllib2
import urllib
import json
import operator


import smap.util as util

from twisted.internet import reactor
from twisted.internet.protocol import ReconnectingClientFactory
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.protocols.basic import LineReceiver
from twisted.web.client import Agent
from twisted.web.http_headers import Headers
from twisted.python import log

try:
    from smap.iface.http.httpcurl import get
except ImportError:
    print >>sys.stderr, """Warning -- can't find httpcurl
  --> Falling back on urllib2
  --> Install pycURL for parallel data downloads"""
    from smap.iface.http.httputils import get

class SmapClient:
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
        """ """
        fp = urllib2.urlopen(self.base + '/api/query?' + 
                             urllib.urlencode(self._build_qdict()),
                             data=q, 
                             timeout=self.timeout)
        rv = json.load(fp)
        fp.close()
        return rv

    def tags(self, qbody, tags='*', nest=False):
        """Look up tags associated with a specific query body"""
        tags = self.query('select %s where %s' % (tags, qbody))
        if not nest:
            return map(lambda t: dict(util.buildkv('', t)), tags)
        else:
            return tags

    def _data(self, qbody, op, **kwargs):
        """Load data for streams matching a particular query"""
        uids = self.query('select distinct uuid where %s' % qbody)
        qdict = self._build_qdict()
        qdict.update(kwargs)

        urls = []
        for u in uids:
            urls.append(str(self.base + ('/api/%s/uuid/' % op) + u + 
                            '?' + urllib.urlencode(qdict)))
        data = get(urls)
        data.sort(key=lambda x: x[1][0]['uuid'])
        uids = map(lambda x: x[1][0]['uuid'], data)
        data = map(lambda x: x[1][0]['Readings'], data)

        return uids, data

    def data(self, qbody, start, end, limit=10000):
        return self._data(qbody, 'data', 
                          starttime=str(int(start)*1000), 
                          endtime=str(int(end)*1000),
                          limit=str(limit))

    def data_uuid(self, uuids, start, end, limit = -1):
        qdict = self._build_qdict()
        qdict['starttime'] = str(int(start)*1000)
        qdict['endtime'] = str(int(end)*1000)
        qdict['limit'] = str(limit)

        urls = []
        for u in uuids:
            urls.append(str(self.base + '/api/data/uuid/' + u +
                            '?' + urllib.urlencode(qdict)))
        data = get(urls)
        map = {}
        for d in data:
          map[d[1][0]['uuid']] = d[1][0]['Readings']

        data = []
        for u in uuids:
          data.append(map[u])
        
        return data

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
    def __init__(self, url, datacb, reconnect=True):
        self.url = url
        self.datacb = datacb
        self.agent = Agent(reactor)
        self.reconnect = reconnect
        self.failcount = 0

    class DataReceiver(LineReceiver):
        """Make our own LineReceiver to read back the streaming data
        from the server.  Use the right delimiter and make sure we can
        handle big objects."""
        MAX_LENGTH = 1e6
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
        if self.failcount < 10:
            self.failcount += 1

    def __request(self, response):
        receiver = RepublishClient.DataReceiver(self)
        receiver.setLineMode()
        response.deliverBody(receiver)

    def _reconnect(self):
        """Exponential backup on the reconnect policy"""
        if self.reconnect and self.failcount < 5:
            print "connection failed, reconnecting in", (self.failcount ** 2)
            reactor.callLater(self.failcount ** 2, self.connect)

    def _connect_failed(self, reason):
        self.failed()
        self._reconnect()

    def connect(self):
        d = self.agent.request('GET',
                               self.url + '/republish',
                               Headers(),
                               None)
        d.addCallback(self.__request)
        d.addErrback(self._connect_failed)

if __name__ == '__main__':
    def cb(line):
        print line
        pass

    c = RepublishClient('http://smote.cs.berkeley.edu:8079', cb)
    c.connect()
    reactor.run()


if __name__ == '__main__':
    import time
    # c = SmapClient('http://new.openbms.org/backend')
    c = SmapClient('http://local.cs.berkeley.edu:8079')
    print c.tags('Metadata/SourceName = "410 Labjacks"')
    print c.latest('Metadata/SourceName = "Cory Hall Dent Meters"', limit=1)
