
import traceback
import operator
import pprint
import time

from twisted.internet import reactor, threads, defer
from twisted.enterprise import adbapi
import psycopg2

import smap.reporting as reporting
import smap.util as util
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
        return settings.rdb.db_open(host=settings.READINGDB_HOST,
                           port=int(settings.READINGDB_PORT))
            
    def put(self, conn):
        # self.pool.append(conn)
        settings.rdb.db_close(conn)

try:
    rdb_pool
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
    """Manage loading data from a single stream from a readingdb
    backend.  Will chain deferred together to return a partial
    timeseries which contains just the uuid and the requested data.
    """
    def __init__(self, uid):
        self.uid = uid

    def _load_data(self, qfunc):
        """Run in thread pool - connect and execute query func
        """
        try:
            conn = rdb_pool.get()
            rv = qfunc(conn)
            return rv
        except:
            raise
        finally:
            rdb_pool.put(conn)

    def _munge_data(self, (request, data)):
        """Tweak the resulting object to be a Timeseries
        """
        if data != None:
            return request, {
                'uuid': self.uid,
                'Readings' : map(lambda x: (x[0] * 1000, x[2]), data)
                }
        return request, None

    def load_data(self, request, method, streamid):
        """Called to kick off a load -- returns a deferred which will
        yield a (request, Timeseries) tuple when it finishes.        
        """
        # if these raise an exception we'll cancel all the loads
        now = int(time.time()) * 1000
        if method == 'data':
            start = int(request.args.get('starttime', [now - 3600 * 24 * 1000])[0])
        else:
            start = int(request.args.get('starttime', [now])[0])
        end = int(request.args.get('endtime', [now])[0])
        limit = int(request.args.get('limit', [-1])[0])
        # print now, start, end, method, streamid

        def mkQueryFunc():
            request_, method_, start_, end_, limit_, streamid_ =  \
                request, method, start, end, limit, streamid
            def queryFunc(db):
                qstart = start_
                qlimit = limit_
                if method_ == 'data':
                    try:
                        rv = []
                        # no limit if zero
                        if qlimit == -1:
                            qlimit = 1000000

                        while True:
                            data = settings.rdb.db_query(db, streamid_, qstart / 1000, end_ / 1000)
                            rv += data[:min(len(data), qlimit)]
                            qlimit -= min(len(data), qlimit)
                            if len(data) < 10000 or \
                               qlimit <= 0: break
                            qstart = (rv[-1][0] + 1) * 1000
                        return request, rv
                    except:
                        traceback.print_exc()
                elif method == 'next':
                    if qlimit == -1: qlimit = 1
                    return request, settings.rdb.db_next(db, streamid_, start_ / 1000, n = qlimit)
                elif method == 'prev':
                    if qlimit == -1: qlimit = 1
                    return request, settings.rdb.db_prev(db, streamid_, start_ / 1000, n = qlimit)
                return request, []
            return queryFunc

        d = threads.deferToThread(self._load_data, mkQueryFunc())
        d.addCallback(self._munge_data)
        d.addErrback(makeErrback(request))
        return d

def data_load_extract(result):
    return result[0][1][0], map(lambda x: x[1][1], result)

def data_load_result(request, method, result):
    count = int(request.args.get('streamlimit', ['10'])[0])
    if count == 0:
        count = len(result)

    if len(result) > 0:
        callbacks = []
        for uid, stream_id in result[:count]:
            loader = DataRequester(uid)
            callbacks.append(loader.load_data(request, method, stream_id))
        d = defer.DeferredList(callbacks)
        d.addCallback(data_load_extract)
        return d
    else:
        return defer.succeed((request, []))

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

    with open('obj.json', 'r') as fp:
        import json
        o = json.load(fp)

    reporting.push_metadata(o)

    data = SmapData(cp)
    d = data._create_ids(1, o)
    def addMetadata(ids):
        m = SmapMetadata(cp)
        d = m.add(1, o, dict(ids))
        return d
    d.addCallback(lambda x: data._get_ids(1, o))
    d.addCallback(addMetadata)

    d.addCallbacks(lambda _: reactor.stop())
    reactor.run()


#     md = ["CALL AddTag('b0e54721-4271-5fe2-97b3-94369cb7ace1', 1313179313000, 1313184118000, 'Metadata/Location/Country', 'USA');"]
#     m = SmapMetadata(cp)
#     d = m._do_metadata(md)
#     if d:
#         d.addCallbacks(lambda _: reactor.stop())
#         reactor.run()
