"""Implementation of the readingdb interface that sticks the data into
postgres.  This lets us avoid having a separate readingdb server for
all installs.
"""

import traceback
import psycopg2
import smap.archiver.settings as settings

def db_open(host=None, port=None):
    db = psycopg2.connect(host=host,
                          database=settings.DB_DB,
                          user=settings.DB_USER,
                          password=settings.DB_PASS)
    return db

def db_query(dbp, streamid, starttime, endtime):
    cursor = dbp.cursor()
    try:
        cursor.execute("""
           SELECT time, seqno, val FROM tsdata 
           WHERE stream_id = %i AND time >= %i AND time < %i
           ORDER BY time ASC LIMIT 10000
    """ % (streamid, starttime, endtime))
        return cursor.fetchall()
    finally:
        cursor.close()

def _mk_insert(streamid, data):
    return ('(%i,' % streamid) + (','.join(map(str, data))) + ")"

def db_add(dbp, streamid, data):
    cursor = dbp.cursor()
    if len(data) == 0: return
    if len(data[0]) == 2:
        istmt = "INSERT INTO tsdata (time, val) VALUES "
    elif len(data[0]) == 3:
        istmt = "INSERT INTO tsdata VALUES "
    else:
        raise Exception

    try:
        for i in xrange(0, len(data), 1000):
            clauses = map(lambda x: _mk_insert(streamid, x), data[i:i+1000])
            cursor.execute(istmt + ','.join(clauses) + ';')
        dbp.commit()
    except:
        raise
    finally:
        cursor.close()

def db_next(dbp, streamid, reference, n = 1):
    cursor = dbp.cursor()
    try:
        cursor.execute("""
           SELECT time, seqno, val FROM tsdata
           WHERE stream_id = %i AND time > %i
           ORDER BY time ASC LIMIT %i
        """ % (streamid, reference, min(n, 10000)))
        return cursor.fetchall()
    finally:
        cursor.close()

def db_prev(dbp, streamid, reference, n = 1):
    cursor = dbp.cursor()
    try:
        cursor.execute("""
           SELECT time, seqno, val FROM tsdata
           WHERE stream_id = %i AND time < %i
           ORDER BY time ASC LIMIT %i
        """ % (streamid, reference, min(n, 10000)))
        return cursor.fetchall()
    finally:
        cursor.close()

def db_del(dbp, streamid, starttime, endtime):
    cursor = dbp.cursor()
    try:
        cursor.execute("""
          DELETE FROM tsdata
          WHERE streamid = %i AND time >= %i AND time < %i
    """ % (streamid, starttime, endtime))
    finally:
        cursor.close()

def db_close(dbp):
    try:
        dbp.close()
    except:
        traceback.print_exc()
