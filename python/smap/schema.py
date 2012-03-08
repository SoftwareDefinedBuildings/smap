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
            break
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
