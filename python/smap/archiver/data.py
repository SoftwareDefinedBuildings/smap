
import traceback
import operator
import pprint

from twisted.internet import reactor, threads, defer
from twisted.enterprise import adbapi
import pgdb as sql

import readingdb as rdb

import smap.reporting as reporting
import smap.util as util
import settings

class ReadingdbPool:
    def __init__(self):
        self.pool = []
        reactor.addSystemEventTrigger('after', 'shutdown', 
                                      self.shutdown)

    def shutdown(self):
        print "ReadingdbPool shutting down:", len(self.pool)
        map(rdb.db_close, self.pool)

    def get(self):
#         if len(self.pool) > 0:
#             return self.pool.pop()
#         else:
        return rdb.db_open(host=settings.READINGDB[0],
                           port=settings.READINGDB[1])
            
    def put(self, conn):
        # self.pool.append(conn)
        rdb.db_close(conn)

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
            vals.append("add_tag(%i,'%s','%s')" % (ids[uid],
                        sql.escape_string(tn),
                        sql.escape_string(tv)))
        ids = dict(ids)
        for path, ts in obj.iteritems():
            addTag(ts['uuid'], 'Path', path)
#             if ids[ts['uuid']] == 1404:
#                 pprint.pprint(ts)
            for name, val in util.buildkv('', ts):
                if name == '/Readings' or name == '/uuid': continue
                addTag(ts['uuid'], name[1:], val)
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
        try:
            r = rdb_pool.get()
            for ts in obj.itervalues():
                data = [(x[0] / 1000, 0, x[1]) for x in ts['Readings']]
                # print "add", len(data), "to", ids[ts['uuid']], data[0][0]
                while len(data) > 128:
                    rdb.db_add(r, ids[ts['uuid']], data[:128])
                    del data[:128]
                if len(data) > 0:
                    rdb.db_add(r, ids[ts['uuid']], data[:128])
        except:
            return False
        finally:
            rdb_pool.put(r)
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
                                                      rv))
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
            uuids.append("add_stream(%i, '%s')" % (subid,
                                                   sql.escape_string(ts['uuid'])))
    
        query += ','.join(uuids)
        return self._run_create(uuids, [], [[]])

    def add(self, subid, obj):
        d = self._create_ids(subid, obj)
        # d.addCallback(lambda rv: self._get_ids(subid, obj))
        d.addCallback(lambda rv: self._add_data(subid, rv, obj))

        # all the errbacks should propagate up to the request handler so we can return a 500
        return d

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
#     o = {u'/demand/CA': {u'Metadata': {u'Location': {u'Country': u'USA', u'State': u'CA', u'Uri': u'http://www.caiso.com/outlook/systemstatus.csv', u'Area': u'CA ISO'}}, u'Description': u'Total demand from the CA ISO', u'Readings': [[1313179313000, 33358]], u'Properties': {u'Timezone': u'America/Los_Angeles', u'UnitofMeasure': u'mWh', u'ReadingType': u'long'}, u'uuid': u'b0e54721-4271-5fe2-97b3-94369cb7ace1'}, u'/demand': {u'Contents': [u'CA']}, u'/': {u'Contents': [u'demand', u'oakland']}}
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
