
import traceback
import operator

from twisted.internet import threads, defer
from twisted.enterprise import adbapi
import MySQLdb as sql

import readingdb as rdb

import smap.reporting as reporting
import smap.util as util
import settings

class ReadingdbPool:
    def __init__(self):
        self.pool = []

    def get(self):
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

    def _get_nearest(self, id, readings):
        conn = rdb_pool.get()
        try:
            nexts = []
            readings.sort(key=lambda x: x[0])
            for i in xrange(0, len(readings)):
                rdb_next = rdb.db_next(conn, id, readings[i][0] / 1000)
                if len(rdb_next) > 0:
                    rdb_next = rdb_next[0][0]
                if i < len(readings) - 1:
                    list_next = readings[i+1][0] / 1000
                else:
                    list_next = 0x7fffffff
                nexts.append(min(rdb_next, list_next) * 1000)
            return nexts
        except:
            traceback.print_exc()
        finally:
            rdb_pool.put(conn)
    
    
    def _add(self, subid, ids, obj):
        """Update the tag set for a reading vector
        """
        def mkquery(uid, ref, nextref, tagname, tagval):
            return "CALL AddTag('%s', %i, %i, '%s', '%s');" % (
                sql.escape_string(uid), ref, nextref * 1000,
                sql.escape_string(tagname[1:]),
                sql.escape_string(tagval))
        rv = []
        ids = dict(ids)
        for path, ts in obj.iteritems():
            if len(ts['Readings']) == 0: continue
            nextrefs = self._get_nearest(ids[str(ts['uuid'])], ts['Readings'])

            min_ts = min(map(operator.itemgetter(0), ts['Readings']))
            max_ts = max(map(operator.itemgetter(0), ts['Readings']))


            # if all the data we're importing has the same tag
            # currently, we can just update tags once, rather than
            # checking for each tag.  this is really the only way of
            # doing things that's even close to efficient... 
            if min(nextrefs[:-1] + [min_ts]) >= min_ts and \
                    min(nextrefs[:-1] + [min_ts]) <= max_ts and \
                    max(nextrefs[:-1] + [max_ts]) >= min_ts and \
                    max(nextrefs[:-1] + [max_ts]) <= max_ts:
                rv.append(mkquery(ts['uuid'], min_ts, max(nextrefs),
                                  '/Path', path))

                for name, val in util.buildkv('', ts):
                    if name == '/Readings' or name == '/uuid': continue
                    query = mkquery(ts['uuid'], 
                                    min_ts, 
                                    max(nextrefs),
                                    name, 
                                    val)
                    rv.append(query)
                continue

            # otherwise check the tags for *every point*
            for i in xrange(0, len(nextrefs)):
                rv.append(mkquery(ts['uuid'], ts['Readings'][i][0],
                                    nextrefs[i], '/Path', path))
                for name, val in util.buildkv('', ts):
                    if name == '/Readings' or name == '/uuid': continue
                    query = mkquery(ts['uuid'], 
                                    ts['Readings'][i][0],
                                    nextrefs[i],
                                    name,
                                    val)
                    rv.append(query)            
        return rv
        
    def _do_metadata(self, queries):
        """Sequentially execute the metdata updates"""
        if len(queries) == 0:
            return
        else:
            # print queries[0]
            d = self.db.runQuery(queries[0])
            d.addCallback(lambda _: self._do_metadata(queries[1:]))
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
        md = SmapMetadata(self.db)
        meta_deferred = md.add(subid, ids, obj)

        ids = dict(ids)
        data_deferred = threads.deferToThread(self._add_data_real, ids, obj)
        
        return defer.DeferredList([meta_deferred, data_deferred], fireOnOneErrback=True, consumeErrors=True)

    def _get_ids(self, subid, obj):
        """Look up the stream ids from the uuids contained in a Timeseries
        """
        uuids = []
        query = "SELECT uuid,id FROM stream WHERE `subscription_id` = %i AND " % int(subid)
        for ts in obj.itervalues():
            uuids.append("`uuid` = '%s'" % sql.escape_string(ts['uuid']))
        query += '(' + ' OR '.join(uuids) + ')'
        return self.db.runQuery(query)

    def _create_ids(self, subid, obj):
        """Create any missing streamids from a Timeseries object.
        This way a select will always return the right results.
        """
        uuids = []
        query = "INSERT IGNORE INTO stream (`subscription_id`, `uuid`) VALUES "
        for ts in obj.itervalues():
            uuids.append("(%i, '%s')" % (subid,
                                         sql.escape_string(ts['uuid'])))
    
        query += ','.join(uuids)
        return self.db.runQuery(query)

    def add(self, subid, obj):
        d = self._create_ids(subid, obj)
        d.addCallback(lambda rv: self._get_ids(subid, obj))
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
