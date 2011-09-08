
import sys
import traceback
import urlparse
import json
import copy
import uuid
import pprint

from zope.interface import implements
from twisted.web import resource, server, proxy
from twisted.web.resource import NoResource
from twisted.internet import reactor, task
# from twisted.web.client import Agent
from twisted.web.client import getPage
from twisted.python import log

from interface import *
from server import RootResource, InstanceResource, ReportingResource
import core
import util
import reporting
import schema

PROXY_ORIGS = [('p0', 'http://localhost:8080')] #, ('p0', 'http://localhost:8080?q=dummy')]
    
class SmapProxyEntity(resource.Resource):
    """A transactional object for managing syncing information with a
    single other sMAP source (pull).  It's called once at the
    beginning when we try to GET the sMAP source to create the initial
    hierarchy, and after that is used to process the inserts from the
    stream of POST messages coming in.

    This object comes either from calling the load() method and
    fetching a url, or decoded from a POST body in render_POST.
    """
    def __init__(self, inst, path):
        self.inst = inst
        self.path = path
        resource.Resource.__init__(self)
    
    def update(self, tree):
        """Update all collections and timeseries with new information
        contained in the "tree" object.
        """
        def update_coll(cur_path, cur):
            cur_path = '/' + self.path + cur_path
            c = self.inst.get_collection(cur_path)
            if not c:
                c = self.inst.add_collection(cur_path)
            c.update(cur)
            try:
                self.inst.reports.publish(cur_path, cur)
            except:
                log.err()

        def update_ts(cur_path, cur):
            cur_path = '/' + self.path + cur_path
            t = self.inst.get_timeseries(cur_path)
            if not t:
                t = core.Timeseries(cur, None)
                self.inst.add_timeseries(cur_path, t, recurse=True)
            else:
                t.update(cur)

            self.inst.reports.publish(cur_path, cur)

        reporting.reporting_map(tree, update_coll, update_ts)
            
    def load(self, url, *args):
        """Load the resource which fetches the whole tree and update
        -- this is used for the initial load. 

        :rvalue: a Deferred which will fire when the update is done.
        It'll yield this SmapProxyEntity object.
        """
        self.url = url
        d = getPage(url + '/data/+')
        def successCb(resp):
            resp = json.loads(resp)
            try:
                url = urlparse.urlparse(self.url)
                try:
                    self.host, self.port = url.netloc.split(':')
                    self.rpath = url.path
                    self.port = int(self.port)
                except Exception, e:
                    log.err()
                    self.host, self.port = url.netloc, 80
                    self.rpath = '/'
                self.update(resp)
                return self
            except Exception, e:
                return None

        d.addCallback(successCb)
        return d

    def render_POST(self, request):
        """All we have to do is republish the incoming data into our
        own reports manager. It will take care of delivering it for
        us.
        """
        obj = json.load(request.content)
        self.update(obj)
        request.finish()
        return server.NOT_DONE_YET


class ProxyResource(resource.Resource):
    """Represents a collection of resources, all of which are actually
    other sMAP sources.  We reverse-proxy them.
    """
    def __init__(self, inst):
        self.collection = core.Collection('/', inst)
        self.child_proxies = {}
        self.collection['Proxy'] = True
        self.inst = inst
        resource.Resource.__init__(self)

    def getChild(self, name, request):
        if name == '':
            return self
        elif name in self.child_proxies:
            host, port, rpath = self.child_proxies[name]
            return proxy.ReverseProxyResource(host, port, rpath + '/data')
        else:
            return NoResource()

    def render_GET(self, request):
        request.setHeader('Content-type', 'application/json')
        d = util.AsyncJSON(self.collection.copy()).startProducing(request)
        d.addBoth(lambda _: request.finish())
        return server.NOT_DONE_YET

    def render_POST(self, request):
        map(self.update_proxy, PROXY_ORIGS)
        request.finish()
        return server.NOT_DONE_YET

    def update_proxy(self, (name, url)):
        this_inst = SmapProxyEntity(self.inst, name)
        d = this_inst.load(url)
        def rootCb(mgr):
            self.child_proxies[mgr.path] = mgr.host, mgr.port, mgr.rpath
        d.addCallback(rootCb)


class PublishResource(resource.Resource):
    """We subscribe to other sMAP sources, and they send us data.  We
    just need to republish that to any interested parties.
    """
    def __init__(self, inst):
        self.inst = inst
        resource.Resource.__init__(self)

    def getChild(self, name, request):
        if name == '':
            return self
        else:
            return SmapProxyEntity(self.inst, name)

def getSite(inst):
    root = RootResource(value=['data', 'reports', 'proxy', 'publish'])
    pr = ProxyResource(inst)
    root.putChild('data', InstanceResource(inst))
    root.putChild('proxy', pr)
    root.putChild('reports', ReportingResource(inst.reports))
    root.putChild('publish', PublishResource(inst))
    map(pr.update_proxy, PROXY_ORIGS)
    return server.Site(root)

if __name__ == '__main__':
    log.startLogging(sys.stdout)
    inst = core.SmapInstance('d85eaa12-ac41-11e0-9f5f-0026bb56ec92')
    reactor.listenTCP(8081, getSite(inst))
    reactor.run()
