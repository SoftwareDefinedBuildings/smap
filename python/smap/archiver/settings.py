
import sys
import ConfigParser

# my local hostname and port to run the twisted server on.  the
# hostname should be something smap sources can send their data to
MY_LOCATION = 'localhost'
MY_PORT = 8079

# how often sMAP report instances should time out
EXPIRE_TIME = None
# how often we should check that we are still subscribed to all the
# sMAP sources.
CHECK_TIME = None

# postgres setup for metadata and other tables
DB_MOD = 'psycopg2'
DB_HOST = 'localhost'
DB_DB = 'archiver'
DB_USER = 'archiver'
DB_PASS = 'password'

# the location of the readingdb server which holds the timeseries
READINGDB_MOD = 'readingdb'
READINGDB_HOST = DB_HOST
READINGDB_PORT = 4242

def import_rdb():
    global rdb
    __import__(READINGDB_MOD)
    rdb = sys.modules[READINGDB_MOD]

def munge_key(k):
    return k.upper().replace(" ", "_")

def load(conffile):
    conf = ConfigParser.ConfigParser('')
    conf.read(conffile)
    if conf.has_section("archiver"):
        for k, v in conf.items("archiver"):
            globals()[munge_key(k)] = v

    # import the readingdb module
    import_rdb()
