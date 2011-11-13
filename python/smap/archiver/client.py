
import sys
import urllib2
import urllib
import json
import operator

import smap.util as util

try:
    from iface.http.httpcurl import get
except ImportError:
    print >>sys.stderr, """Warning -- can't find httpcurl
  --> Falling back on urllib2
  --> Install pycURL for parallel data downloads"""
    from iface.http.httputils import get

class SmapClient:
    def __init__(self, base, key=None, private=False, timeout=5.0):
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

    def _query(self, q):
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
        tags = self._query('select %s where %s' % (tags, qbody))
        if not nest:
            return map(lambda t: dict(util.buildkv('', t)), tags)
        else:
            return tags

    def _data(self, qbody, op, **kwargs):
        """Load data for streams matching a particular query"""
        uids = self._query('select distinct uuid where %s' % qbody)
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
                          starttime=str(start*1000), 
                          endtime=str(end*1000),
                          limit=str(limit))

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


if __name__ == '__main__':
    import time
    # c = SmapClient('http://new.openbms.org/backend')
    c = SmapClient('http://local.cs.berkeley.edu:8079')
    print c.tags('Metadata/SourceName = "410 Labjacks"')
    print c.latest('Metadata/SourceName = "Cory Hall Dent Meters"', limit=1)
