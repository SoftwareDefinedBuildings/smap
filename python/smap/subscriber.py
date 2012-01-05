
import sys
import uuid
import json

import pprint
import traceback

from twisted.internet import reactor, task, defer, threads
from twisted.web.client import Agent
from twisted.web.http_headers import Headers
from twisted.python import log
from twisted.web import resource, server, proxy

import util
import reporting 

class SmapConsumer(resource.Resource):
    def __init__(self):
        self.streams = {}
        resource.Resource.__init__(self)

    def add(self, report):
        try:
            reporting.push_metadata(report)
        except Exception, e:
            traceback.print_exc()
        for path, val in report.iteritems():
            with open('data/' + path.replace('/', '-'), 'a') as fp:
                readings = val.pop('Readings')
                if len(readings) == 0: continue
                val.pop('uuid')
                for k, v in util.buildkv('', val):
                    print >>fp, "# %s = %s" % (k[1:], v)
                for rv in readings:
                    print >>fp, rv['ReadingTime'], rv['Reading']

    isLeaf = True
    def render_POST(self, request):
        print 
        obj = json.load(request.content)
        # pprint.pprint(obj)
        self.add(obj)
        request.finish()
        return server.NOT_DONE_YET
        

class SmapSubscriber:
    """Class to maintain a subscription to a sMAP source.
    """
    def __init__(self, url, dest, resource='/+', id=None, expire_time=60, min_period=0):
        """
        :param string url: The URL of the sMAP server
        :param string dest: The URL of the data destination
        :param uuid.UUID id: id of the reporting instance to touch
        :param string expire_time: how long before the sMAP server
         automatically deletes the report, in seconds
        :param string min_period: reporting min period value -- don't
         deliver reports more frequently than this.
        """
        self.url = url
        self.expire_time = expire_time
        if not id: id = uuid.uuid1()
        self.rpt_obj = {
            'uuid' : str(id),
            'ReportDeliveryLocation' : [dest],
            'ReportResource' : resource,
            'MinPeriod': int(min_period * 1000)
            }
        self.is_subscribed = False

    def is_subscribed(self):
        return self.is_subscribed

    def subscribe(self):
        """Send or re-send the request for data.
        """
        if self.expire_time:
            self.rpt_obj['ExpireTime'] = util.now() + int(self.expire_time * 1000)
        agent = Agent(reactor)
        d = agent.request('PUT',
                          self.url + '/reports/' + str(self.rpt_obj['uuid']),
                          Headers({'Content-type' : ['application/json']}),
                          util.AsyncJSON(self.rpt_obj))
        def eb(request):
            self.is_subscribed = False
            log.err("Subscription failed to " + self.url)
            return False
        def sb(request):
            if not isinstance(request, bool) and request.code in [200, 201]:
                log.msg("Successfully subscribed to " + self.url)
                self.is_subscribed = True
                return True
            else:
                return eb(request)
        d.addErrback(eb)
        d.addCallback(sb)
        return d

    def unsubscribe(self):
        """Delete an installed reporting instance
        """
        agent = Agent(reactor)
        d = agent.request('DELETE',
                          self.url + '/reports/' + str(self.rpt_obj['uuid']),
                          Headers({'Content-type' : ['application/json']}))
        def sb(request):
            if not isinstance(request, bool) and request.code in [200, 201, 404]:
                self.is_subscribed = False
                log.msg("unsubscribed from " + self.url)
                return True
            else: return False
        d.addCallback(sb)
        return d
           

def _subscribe(result):
    """
    Called with list of sMAP sources to subscribes to
    Returns map of uuid => :py:class:`smap.subscriber.SmapSubcriber` instances 
    """
    subs = {}
    for (url, id, key) in result:
        dest = 'http://%s:%s/add/%s' % (settings.MY_LOCATION[0],
                                         settings.MY_LOCATION[1],
                                         key)
        s =SmapSubscriber(url, dest, id=id, expire_time=None)
        s.subscribe()
        subs[id] = s
    return subs

def subscribe(db):
    """Look up all of the sMAP sources we should subscribe to
    """
    d = db.runQuery("""
       SELECT url, uuid, key 
       FROM subscription 
       WHERE url IS NOT NULL AND url != ''""")
    d.addCallback(_subscribe)
    return d


