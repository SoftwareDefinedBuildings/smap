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
import os
from configobj import ConfigObj
from validate import Validator

from twisted.python import log

def import_rdb(settings):
    global rdb
    try:
        __import__(settings['readingdb']['module'])
        rdb = sys.modules[settings['readingdb']['module']]
        try:
            rdb.db_setup(settings['readingdb']['host'],
                         settings['readingdb']['port'])
        except AttributeError:
            pass
    except ImportError:
        pass

def load(conffile):
    config = ConfigObj(conffile,
                       configspec=os.path.join(os.path.dirname(sys.modules[__name__].__file__),
                                               "settings.spec"),
                       stringify=True,
                       indent_type='  ')
    val = Validator()
    config.validate(val)
    # import the readingdb module
    import_rdb(config)
    return config

# try to load the site conf
conf = load('/etc/smap/archiver.ini')

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
