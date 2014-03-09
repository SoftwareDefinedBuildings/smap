
import csv
import math

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

    def unregisterProducer(self):
        self.consumer.unregisterProducer()

    def write(self, data):
        self.consumer.write(json.dumps(data))
        self.consumer.write("\n")

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
