
import traceback
import time
import cjson
import json
import operator
import urllib

from twisted.internet import threads, defer
from twisted.web import resource, server
from twisted.web.resource import NoResource
import MySQLdb as sql

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
    def _load_data(self, qfunc):
        try:
            conn = data.rdb_pool.get()
            rv = qfunc(conn)
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
            data = cjson.encode(map(mungeData, data))
            request.write(data)
            request.finish()

    def render_GET(self, request, streamid):
        now = int(time.time()) * 1000
        try:
            start = int(request.args.get('starttime', [now - 3600 * 24])[0])
            end = int(request.args.get('endtime', [now])[0])
            limit = int(request.args.get('limit', [-1])[0])
            method = request.args.get('direction', ["query"])[0]
        except:
            request.setResponseCode(400)
            request.finish()
            return

        def mkQueryFunc():
            method_, start_, end_, limit_, streamid_ =  \
                method, start, end, limit, streamid
            def queryFunc(db):
                qstart = start_
                qlimit = limit_
                if method_ == 'query':
                    try:
                        rv = []
                        # no limit if zero
                        if qlimit == -1:
                            qlimit = 1000000

                        while True:
                            data = rdb.db_query(db, streamid_, qstart / 1000, end_ / 1000)
                            rv += data[:min(len(data), qlimit)]
                            qlimit -= min(len(data), qlimit)
                            qstart = (rv[-1][0])*1000
                            if len(data) < 10000 or \
                               qlimit <= 0: break
                        return rv
                    except:
                        traceback.print_exc()
                elif method == 'next':
                    if qlimit == -1: qlimit = 1
                    return rdb.db_next(db, streamid_, start_ / 1000, n = qlimit)
                elif method == 'prev':
                    if qlimit == -1: qlimit = 1
                    return rdb.db_prev(db, streamid_, start_ / 1000, n = qlimit)
                return None
            return queryFunc

        d = threads.deferToThread(self._load_data, mkQueryFunc())
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
FROM metadata2 m
WHERE stream_id = %s""", (int(streamid), ))
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
FROM subscription sub, stream s, metadata2 m
WHERE tagname = 'Path' AND
    m.stream_id = s.id AND
    s.subscription_id = sub.id AND
    sub.id = %s 
""", (int(request.prepath[-1]), ))
            d.addCallback(lambda x: self._done_streams(request, x))
            d.addErrback(makeErrback(request))
        return server.NOT_DONE_YET


class QueryResource(ApiResource):
    def render_reply(self, request, result):
        d = util.AsyncJSON(map(operator.itemgetter(0), result)).startProducing(request)
        d.addBoth(lambda _: request.finish())

    def build_query(self, tags):
        now = int(time.time()) * 1000
        clauses = []
        for (k, v) in tags:
            if v != None:
                clauses.append("(tagname = '%s' AND tagval = '%s')" % (sql.escape_string(k),
                                                                       sql.escape_string(v)))
            else: break
        if len(clauses) == 0 and len(tags) == 0:
            query = """
SELECT DISTINCT tagname
FROM metadata2 m""" 
        elif tags[-1][0] == 'uuid':
            query = """
SELECT DISTINCT s.uuid 
FROM metadata2 AS m, stream AS s
WHERE m.stream_id IN 
  (SELECT oq.stream_id FROM
    (SELECT stream_id, count(stream_id) AS cnt
     FROM metadata2
     WHERE (%s)
     GROUP BY stream_id) AS oq
   WHERE oq.cnt = %i) AND
m.stream_id = s.id;""" % (' OR '.join(clauses), 
                             len(clauses))

        elif len(clauses) == 0:
            query = """
SELECT DISTINCT tagval FROM metadata2
WHERE tagname = '%s'
""" % (tags[-1][0])
        elif tags[-1][1] == None or tags[-1][1] == '':
            query = """
SELECT DISTINCT m.tagval 
FROM metadata2 AS m
WHERE m.stream_id IN 
  (SELECT oq.stream_id FROM
    (SELECT stream_id, count(stream_id) AS cnt
     FROM metadata2
     WHERE (%s)
     GROUP BY stream_id) AS oq
   WHERE oq.cnt = %i) AND
m.tagname = '%s';""" % (' OR '.join(clauses), 
                             len(clauses),
                             tags[-1][0])
        else:
            query = """
SELECT DISTINCT m.tagname
FROM metadata2 AS m
WHERE m.stream_id IN 
  (SELECT oq.stream_id FROM
    (SELECT stream_id, count(stream_id) AS cnt
     FROM metadata2
     WHERE (%s)
     GROUP BY stream_id) AS oq
   WHERE oq.cnt = %i);""" % (' OR '.join(clauses),
                             len(clauses))

        print query
        d = self.db.runQuery(query)
        return d

    isLeaf = True
    def render_GET(self, request):
        path = map(lambda x: x.replace('__', '/'), request.postpath)
        path = map(urllib.unquote, path)
        d = self.build_query(zip(path[::2], 
                                path[1::2] + [None]))
        d.addCallback(lambda r: self.render_reply(request, r))
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
        elif name == 'query':
            return QueryResource(self.db)
        else:
            return self

    def render_GET(self, request):
        if len(request.prepath) == 1:
            print "dumping"
            return json.dumps({'Contents': ['streams', 'query', '<uuid>']})
        d = self.db.runQuery("SELECT id FROM stream WHERE uuid = %s", 
                             (request.prepath[1], ))
        print "checking", request.prepath[1]
        d.addCallback(lambda x: self._lookup_method(request, x))
        d.addErrback(makeErrback(request))
        return server.NOT_DONE_YET


if __name__ == '__main__':
    import settings
    from twisted.enterprise import adbapi
    from twisted.internet import reactor

    # connect to the mysql db
    cp = adbapi.ConnectionPool('MySQLdb', 
                               host=settings.MYSQL_HOST,
                               db=settings.MYSQL_DB,
                               user=settings.MYSQL_USER,
                               passwd=settings.MYSQL_PASS)
    tr = QueryResource(cp)

    d = tr.build_tree([('Metadata/Location/Campus', 'UCB'), 
                       ('Metadata/Location/Building', 'Soda Hall'),
                       ('Path', None)])
    d.addCallback(lambda _:reactor.stop())
    reactor.run()
