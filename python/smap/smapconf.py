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

import logging
from twisted.python import log

# default configuration 
SERVER = {
    'port' : 8080,
    }

LOGGING = {
    # configure logging to sentry via raven
#         'raven': { 
#             'dsn': 'twisted+http://a888206fd60f4307a7b1a880d1fe04fe:15ecf70787b0490880c712d8469459bd@localhost:9000/2'
#             },
    'console': {
        'level': 'INFO'
        }
    
    }

# guess where the html might be...
try:
    if not 'docroot' in SERVER:
        path = os.path.dirname(sys.modules[__name__].__file__)
        path = os.path.join(path, "data")
        SERVER['docroot'] = path
except:
    SERVER['docroot'] = None

class InverseFilter(logging.Filter):
    def filter(self, record):
        return not logging.Filter.filter(self, record)

def start_logging():
    observer = log.PythonLoggingObserver()
    observer.start()

    for logtype, config in LOGGING.iteritems():
        if logtype == "raven":
            from raven.handlers.logging import SentryHandler
            lvl = getattr(logging, config.get('level', 'info').upper())
            handler = SentryHandler(config["dsn"])
            handler.setLevel(lvl)
            # don't try to log sentry errors with sentry
            handler.addFilter(InverseFilter('sentry'))
            logging.getLogger().addHandler(handler)
            print "Starting sentry logging [%s] with destination %s"% (
                config.get('level', 'info').upper(), config["dsn"])
        elif logtype == 'console':
            console = logging.StreamHandler()
            lvl = getattr(logging, config.get('level', 'info').upper())
            console.setLevel(lvl)
            formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
            console.setFormatter(formatter)
            logging.getLogger().addHandler(console)
            print "Starting console logging [%s]" % config.get('level', 'info').upper()
