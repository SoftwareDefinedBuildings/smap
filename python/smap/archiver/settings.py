"""
Copyright (c) 2011, 2012, Regents of the University of California
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions 
are met:

 - Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
 - Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the
   distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL 
THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED 
OF THE POSSIBILITY OF SUCH DAMAGE.
"""
"""
@author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
"""

import sys
import ConfigParser

from twisted.python import log

# my local hostname and port to run the twisted server on.  the
# hostname should be something smap sources can send their data to
MY_LOCATION = 'localhost'
# default port to run the archiver on
MY_PORT = 8079
# default backend to use if none is specified 
DEFAULT_BACKEND = 'http://localhost:8079/api/query'

# how often sMAP report instances should time out
EXPIRE_TIME = None
# how often we should check that we are still subscribed to all the
# sMAP sources.
CHECK_TIME = None

# postgres setup for metadata and other tables
DB_MOD = 'smap.archiver.settings'
DB_HOST = 'localhost'
DB_DB = 'archiver'
DB_USER = 'archiver'
DB_PASS = 'password'
DB_PORT = 5432

# the location of the readingdb server which holds the timeseries
READINGDB_MOD = 'readingdb'
READINGDB_HOST = DB_HOST
READINGDB_PORT = 4243

def import_rdb():
    global rdb
    try:
        __import__(READINGDB_MOD)
        rdb = sys.modules[READINGDB_MOD]
        try:
            rdb.db_setup(READINGDB_HOST, int(READINGDB_PORT))
        except AttributeError:
            pass
    except ImportError:
        pass

def munge_key(k):
    return k.upper().replace(" ", "_")

def load(conffile):
    conf = ConfigParser.ConfigParser('')
    conf.read(conffile)
    if conf.has_section("archiver"):
        for k, v in conf.items("archiver"):
            globals()[munge_key(k)] = v 
            log.msg(k + ": " + v)
    # import the readingdb module
    import_rdb()

# try to load the site conf
load('/etc/smap/archiver.ini')
import_rdb()

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    # make sure we don't kill people not trying to use the archiver
    pass
else:
    def connect(*args, **kwargs):
        conn = psycopg2.connect(*args, **kwargs)
        psycopg2.extras.register_hstore(conn)
        return conn
