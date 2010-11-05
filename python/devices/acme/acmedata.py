
import sys
import logging
import time

import BinaryJson
import RefImpl

__schemas__ = [
    # AcmeStatus
    { 
        'name' : 'http://webs.cs.berkeley.edu/schema/meter/status',
        'description' : 'The status of a meter',
        'type' : 'object',
        'properties' : {
            'localtime' : { 'type' : 'integer' }
            }
        }
    ]

class DataCollection(RefImpl.Collection):
    def __init__(self):
        RefImpl.Collection.__init__(self, {'readings'  : None,
                                           'params'    : None,
                                           'formatting': None,
                                           'profile'   : None,
                                           'status'    : AcmeStatus()})

class ReportingCollection(RefImpl.Collection):
    def __init__(self):
        RefImpl.Collection.__init__(self, {'create'   : None,
                                           'reports'  : None})                                   

class AcmeStatus:
    def do_GET(self, request):
        return { '$schema' : {'$ref' : 'http://webs.cs.berkeley.edu/schema/meter/status'},
                 'localtime' : int(time.time()) }

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

    c = RefImpl.Collection( {"data"      : DataCollection(), 
                             "reporting" : ReportingCollection()} )

    ref = RefImpl.RefImpl(c)

    BinaryJson.schema_sources.append(BinaryJson.ListSchemaSource(__schemas__))
    ref.run()
