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

import csv
import math
import datetime

from twisted.internet import interfaces, reactor
from zope.interface import implements

from smap.contrib import dtutil
import smap.sjson as json

def make_time_formatter(request, stags):
    """Return a function that propertly formats timestamps for a
    particular request.
    """
    if 'timefmt' in request.args:
        try:
            tz = stags['Properties']['Timezone']
        except KeyError:
            tz = 'Utc'
        tz = dtutil.gettz(tz)

        # potentially do timestamp stringification here.
        # this could be a bit slow for large datasets...
        if request.args['timefmt'][0] == 'iso8601': 
            fmt = dtutil.iso8601
        elif request.args['timefmt'][0] == 'excel':
            fmt = fmt = dtutil.excel
        else:
            fmt = lambda dt, tz: dtutil.strftime_tz(dt, '%s')
            tz = dtutil.gettz('Utc')
        def format(t):
            return fmt(dtutil.ts2dt(t / 1000), tz)
        return format
    else:
        return lambda x: str(int(x))

class JsonConsumer(object):
    implements(interfaces.IConsumer)
#    implements(interfaces.IPushProducer)

    def __init__(self, consumer):
        self.consumer = consumer
    
    def pauseProducing(self):
        self.producer.pauseProducing()

    def resumeProducing(self):
        self.producer.resumeProducing()

    def registerProducer(self, producer, streaming):
        assert streaming == True
        self.producer = producer
        self.consumer.registerProducer(self, True)
        self.consumer.setHeader("Content/Type", "application/json")

    def unregisterProducer(self):
        self.consumer.unregisterProducer()

    def write(self, data):
        self.consumer.write(json.dumps(data))
        self.consumer.write("\r\n")

    def finish(self):
        self.consumer.finish()

    def stopProducing(self):
        self.producer.stopProducing()

class CsvConsumer(object):
    implements(interfaces.IConsumer)

    def __init__(self, consumer):
        self.consumer = consumer
        self.writer = csv.writer(consumer)
        self.sent_header = False
    
    def pauseProducing(self):
        self.producer.pauseProducing()

    def resumeProducing(self):
        self.producer.resumeProducing()

    def registerProducer(self, producer, streaming):
        assert streaming == True
        self.producer = producer
        self.consumer.registerProducer(self, True)
        self.consumer.setHeader("Content-Type", "text/csv")

    def unregisterProducer(self):
        self.consumer.unregisterProducer()

    def write(self, data):
        if not len(data): return
        if not isinstance(data, list): return
        timeformat = make_time_formatter(self.consumer, data[0])

        if not self.sent_header:
            self.sent_header = True
            if "ColumnName" in data[0]:
                self.consumer.write("time," + data[0]["ColumnName"] + "\r\n")

        data = data[0]["Readings"]
        def format_number(n):
            return '' if math.isnan(n) else str(n)

        for row in data:
            self.consumer.write(timeformat(row[0]) + ',')
            self.consumer.write(','.join(map(format_number, row[1:])))
            self.consumer.write('\r\n')

    def finish(self):
        self.consumer.finish()

    def stopProducing(self):
        self.producer.stopProducing()

def make_outputfilter(request):
    if 'format' in request.args and 'csv' in request.args['format']:
        return CsvConsumer(request)
    else:
        return JsonConsumer(request)
