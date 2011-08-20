
import sys
import os
import uuid
import json
import glob

from avro import schema
from avro import io


class SmapSchemas:
    SCHEMAS = [
        # new extension types
        "uuid", 
        "UnitofTime", "Duration", 
        "ReadingType", "ReadingValue",

        'InstrumentMetadata', 'LocationMetadata',
        
        # timeseries subobjects
        "Actuator", 
        "Properties", "Metadata", 
        "TimeSeries", "Collection",
        "Reporting"]
    def __init__(self, schemadir=".."):
        self.names = schema.Names()
        for sf in self.SCHEMAS:
            print "Loading", sf
            with open(os.path.join(schemadir, sf.lower() + ".av"), "r") as fp:
                obj = json.load(fp)
                s = schema.make_avsc_object(obj, self.names)

    def write(self, fp, datum, schema):
        sch = self.names.get_name('edu.berkeley.cs.local.' + schema, None)
        dwriter = io.DatumWriter(writers_schema=sch)
        dwriter.write(datum, io.BinaryEncoder(fp))

    def read(self, fp, schema):
        sch = self.names.get_name('edu.berkeley.cs.local.' + schema, None)
        dreader = io.DatumReader(writers_schema=sch, readers_schema=sch)
        return dreader.read(io.BinaryDecoder(fp))

if __name__ == '__main__':
    import time
    myreading = {
        'Reading' : 12,
        'ReadingTime' : int(time.time())
        }
    mytimeseries = {
        'uuid' : uuid.uuid1().bytes,
        # 'Description' : "This is a stream",
        'Readings' :  [{'ReadingTime' : int(time.time() * 1000), "Reading" : "foo"}],
        'Parameter' : {
            'UnitofMeasure' : 'eV',
            'ReadingType' : 'double',
#             'UnitofTime' : 'second',
#             'SamplingPeriod' : {
#                 'Value'  : 1,
#                 'UnitofTime' : 'day'
#                 },
            },
#        'Metadata' : { 'Extra' : {} },
        }

    mycollection = {
        'uuid' : uuid.uuid1().bytes,
        'Proxy' : False,
        'Contents' : [
            'ts0'
            ]
        }
    print mycollection

    import random
    now = int(time.time())  * 1000
    rreadings = [{'ReadingTime' : now + i,
                  'Reading': int(random.random() * 100)}
                 for i in xrange(0, 100)]
    # print rreadings
        
    
    s = SmapSchemas()
    # s.write(sys.stderr, myreading, 'ReadingRecord')
    # s.write(sys.stderr, mytimeseries, 'Timeseries')
    # s.write(sys.stderr, myparameter, 'Parameter')
    s.write(sys.stderr, mycollection, 'Collection')
    #print s.read(sys.stdin, 'Timeseries')
