
import os
import json
import uuid
from avro import schema, io

NAMESPACE = "edu.berkeley.cs.local"
SCHEMA_DIR = os.path.join(os.path.dirname(__file__), "../schema")
SCHEMA_NAMES = schema.Names(default_namespace=NAMESPACE)
SCHEMAS = [
    # new extension types
    "uuid", "version",
    "UnitofTime", "Duration", 
    "ReadingType", "ReadingValue",
    
    'InstrumentMetadata', 'LocationMetadata',
    
    # timeseries subobjects
    "Actuator", 
    "Properties", "Metadata", 
    "TimeSeries", "CollectionList", "Collection",
    "Reporting"]

# load all the schemas when we check an object
for sf in SCHEMAS:
    # print "Loading", sf
    with open(os.path.join(SCHEMA_DIR, sf.lower() + ".av"), "r") as fp:
        obj = json.load(fp)
        s = schema.make_avsc_object(obj, SCHEMA_NAMES)
        
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
    id = obj.get('uuid', None)
    if id: obj['uuid'] = id.bytes
    rv = io.validate(s, obj)
    if id: obj['uuid'] = id
    return rv


# validate("Timeseries", None)
