
import os
import sys
import json
import uuid
from avro import schema, io

import util
import pkgutil

NAMESPACE = "edu.berkeley.cs.local"
SCHEMA_NAMES = schema.Names(default_namespace=NAMESPACE)
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
SCHEMA_OBJECTS = []

# load all the schemas when we check an object
for sf in SCHEMAS:
    # print "Loading", sf
	
    dirs = [os.path.dirname(sys.modules[__name__].__file__), sys.prefix]
    obj = None
    for d in dirs:
        try:
            path = os.path.join(d, 'schema', sf.lower() + '.av')
            obj = json.load(open(path, 'r'))
        except:
            pass
    if obj == None:
        raise Exception('Cannot load schema: ' + sf.lower())
    
    s = schema.make_avsc_object(obj, SCHEMA_NAMES)
    SCHEMA_OBJECTS.append(obj)
        
def validate(schema, obj):
    """Validate an object against its schema.

    Right now, this just checks it against the Avro schema; however in
    the future we will want to impose additional constraints which
    aren't expressable in the schema.
    """
    if schema == 'uuid' and isinstance(obj, uuid.UUID):
        return True
    elif schema == 'Readings':
        return True

    s = SCHEMA_NAMES.get_name(schema, None)
    # swap the uuid for the byte-packed encoding we use with avro
    try:
        id = obj.get('uuid', None)
        if util.is_string(id):
            id = uuid.UUID(id)

        if id: obj['uuid'] = id.bytes
        rv = io.validate(s, obj)
        if id: obj['uuid'] = id
        return rv
    except:
        return False

def filter_fields(schema, obj):
    rv = {}
    schema = util.find(lambda x: x.get("name", "") == schema, SCHEMA_OBJECTS)
    if not schema: 
        return obj

    for field in [x['name'] for x in schema['fields']]:
        if field in obj:
            rv[field] = obj[field]
            
    return rv

# validate("Timeseries", None)
