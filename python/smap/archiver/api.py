
import traceback
import time
import json
import operator

from twisted.internet import threads, defer
from twisted.web import resource, server
from twisted.web.resource import NoResource

import readingdb as rdb

import smap.util as util
import data

def makeErrback(request_):
    request = request_
    def errBack(outp):
        try:
            request.setResponseCode(500)
            request.finish()
        except:
            traceback.print_exc()

class ApiResource(resource.Resource):
    def __init__(self, db):
        self.db = db
        resource.Resource.__init__(self)

class DataResource(ApiResource):
    def _load_data(self, streamid, start, end):
        try:
            conn = data.rdb_pool.get()
            rv = rdb.db_query(conn, streamid, start / 1000, end / 1000)
            return rv
        except:
            return None
        finally:
            data.rdb_pool.put(conn)

    def _send_reply(self, request, data):
        def mungeData(rec):
            return (rec[0] * 1000, rec[2])

        if data == None:
            request.setResponseCode(500)
            request.finish()
        else:
            data = map(mungeData, data)
            d = util.AsyncJSON(data).startProducing(request)
            d.addBoth(lambda _: request.finish())            

    def render_GET(self, request, streamid):
        try:
            start = int(request.args['starttime'][0])
            end = int(request.args['endtime'][0])
        except:
            traceback.print_exc()
            request.setResponseCode(400)
            request.finish()

        d = threads.deferToThread(self._load_data, streamid, start, end)
        d.addCallback(lambda x: self._send_reply(request, x))
        d.addErrback(makeErrback(request))


class TagsResource(ApiResource):
    def _done(self, request, result):
        result = dict(result)
        result['uuid'] = request.prepath[1]
        result['ValidTime'] = str(self.when)

        d = util.AsyncJSON(dict(result)).startProducing(request)
        d.addBoth(lambda _: request.finish())

    def render_GET(self, request, streamid, when=None):
        if not when:
            when = int(time.time()) * 1000
        self.when = when
        d = self.db.runQuery("""
SELECT tagname, tagval
FROM metadata m
WHERE `anchor` <= %s AND `anchor` + `duration` > %s AND `stream_id` = %s""",
                             (when, when, int(streamid)))
        d.addCallback(lambda x: self._done(request, x))
        d.addErrback(makeErrback(request))

class SubscriptionResource(ApiResource):
    """Show the client a list of sMAP sources, or a small description
    of the streams associated with one subscription.
    """
    def getChild(self, name, resource):
        return self

    def _done_subs(self, request, result):
        try:
            result = [{'id' : x[0],
                       'SmapUrl' : x[1],
                       'ReportResource' : x[2]} for x in result]
            d = util.AsyncJSON(result).startProducing(request)
            d.addBoth(lambda _: request.finish())
        except:
            traceback.print_exc()

    def _done_streams(self, request, result):
        result = [{'Path' : x[0],
                   'uuid' : x[1]} for x in result]
        result.sort(key=operator.itemgetter('Path'))
        d = util.AsyncJSON(result).startProducing(request)
        d.addBoth(lambda _: request.finish())

    def render_GET(self, request):
        if len(request.prepath) == 2 or \
                (len(request.prepath) == 3 and request.prepath[-1] == ''):
            d = self.db.runQuery("""
SELECT id, url, resource
FROM subscription""")
            d.addCallback(lambda x: self._done_subs(request, x))
            d.addErrback(makeErrback(request))
        else:
            when = int(time.time()) * 1000
            
            d = self.db.runQuery("""
SELECT m.tagval, s.uuid
FROM subscription sub, stream s, metadata m
WHERE tagname = 'Path' AND
    m.stream_id = s.id AND
    s.subscription_id = sub.id AND
    sub.id = %s AND
    m.anchor <= %s AND m.anchor + m.duration > %s
""", (int(request.prepath[-1]), when, when))
            d.addCallback(lambda x: self._done_streams(request, x))
            d.addErrback(makeErrback(request))
        return server.NOT_DONE_YET

class Api(resource.Resource):
    def __init__(self, db):
        self.db = db
        resource.Resource.__init__(self)

    def _lookup_method(self, request, id):
        if len(id) != 1:
            request.setResponseCode(404)
            request.finish()
            return
        streamid = id[0][0]
        if request.prepath[2] == 'tags':
            resource = TagsResource(self.db)
        elif request.prepath[2] == 'data':
            resource = DataResource(self.db)
        else:
            request.write('Error')
            request.finish()
            return

        return resource.render_GET(request, streamid)

    def getChild(self, name, request):
        if name == 'streams':
            return SubscriptionResource(self.db)
        else:
            return self

    def render_GET(self, request):
        d = self.db.runQuery("SELECT id FROM stream WHERE `uuid` = %s", 
                             (request.prepath[1], ))
        print "checking", request.prepath[1]
        d.addCallback(lambda x: self._lookup_method(request, x))
        d.addErrback(makeErrback(request))
        return server.NOT_DONE_YET
