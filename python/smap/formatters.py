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

import re
import zlib

from zope.interface import implements
from twisted.internet.task import cooperate
from twisted.web import iweb

from smap import schema
from smap.sjson import AsyncJSON, dumps
from smap.util import push_metadata, join_path, split_path
from smap.contrib import dtutil
# from smap.core import SmapException

class AsyncFormatter(object):
    """Boilerplate for an async producer"""
    implements(iweb.IBodyProducer)
    content_encoding = None

    def __init__(self, value):
        self._value = value
        self.length = iweb.UNKNOWN_LENGTH

    def startProducing(self, consumer):
        self._consumer = consumer
        self._task = cooperate(self._produce())
        d = self._task.whenDone()
        d.addBoth(self._unregister)
        return d
    
    def pauseProducing(self):
        self._task.pause()

    def resumeProducing(self):
        self._task.resume()

    def stopProducing(self):
        self._task.stop()

    def _unregister(self, passthrough): 
        return passthrough

class StaticProducer(AsyncFormatter):
    BLKSZ = 1024

    def _produce(self):
        for i in xrange(0, len(self._value), self.BLKSZ):
            self._consumer.write(self._value[i:i+self.BLKSZ])
            yield None

class GzipJson(StaticProducer):
    content_type = 'application/json'
    content_encoding = 'gzip'

    def __init__(self, value):
        value = dumps(value)
        self._value = zlib.compress(value)
        print "%i -> %i" % (len(value), len(self._value))
        self.length = len(self._value)

class GzipAvro(StaticProducer):
    content_type = 'avro/binary'
    content_encoding = 'gzip'

    def __init__(self, value):
        json = dumps(value)
        avro = schema.dump_report(value)
        self._value = zlib.compress(avro)
        print "json: %i gzip-json: %i avro: %i gzip-avro: %i" % (
            len(json), len(zlib.compress(json)), len(avro), len(self._value))
        self.length = len(self._value)

class AsyncSmapToCsv(AsyncFormatter):
    """Convert a sMAP report to a simplified CSV format for dumb clients"""
    content_type = 'text/csv'

    @staticmethod
    def _format_point(path, uid, val):
        return ','.join([uid, path, str(int(val[0] / 1000)), str(val[1])])

    def _produce(self):
        for path, val in self._value.iteritems():
            if not 'uuid' in val: continue
            self._consumer.write('\n'.join((AsyncSmapToCsv._format_point(path, 
                                                                         str(val['uuid']), 
                                                                         p) 
                                            for p in val['Readings'])))
            yield None

__FORMATTERS__ = {
    'json': AsyncJSON,
    'gzip-json': GzipJson,
    'gzip-avro': GzipAvro,
    'csv': AsyncSmapToCsv,
    }

def get_formatter(format):
    return __FORMATTERS__[format]

def load_csv(data):
    """Load csv data from a string into an approximate sMAP object"""
    obj = {}
    for line in re.split("(\r?\n)|$", data):
        parts = line.split(',')
        if len(parts) != 4:
            raise Exception("Invalid CSV line: " + line)
        uid, path, ts, val = parts

        if not path in obj: 
            obj[path] = {'uuid': uid}
        if obj[path]['uuid'] != uid:
            raise Exception("Multiple uuids with the same path: " + path)
        if not 'Readings' in obj[path]:
            obj[path]['Readings'] = []
        obj[path]['Readings'].append([int(ts) * 1000, float(val)])

    return obj
