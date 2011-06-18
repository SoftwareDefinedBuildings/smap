
import sys
import logging
import time
import pickle
sys.path.append('../../newlib')

import SmapHttp
import SmapInstance
import SmapPoint
from SmapAuthorization import authenticated, Auth
from SmapActuate import BinaryActuator
import smaplog


class TestAuth:
    @authenticated(['CAP_HAS_SSL'])
    def http_get(self, request, resource, query=None):
        print resource
        return resource

class TestActuator(BinaryActuator):
    state = 1
    def get_state(self, req):
        return self.state
    def set_state(self, req, new_state):
        self.state = new_state

if __name__ == '__main__':
    smaplog.start_log(screenLevel=logging.DEBUG)

    a = TestAuth()

    data = {
        '0' : {'sensor' :
                   {'0' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='kW',multiplier=None,
                                                                   divisor=None,type='sensor',
                                                                   ctype='sensor'),
                                              SmapPoint.Parameter(interval=5, time='second')) } ,
               'actuate' : {
                '0' : TestActuator() 
                     },
               }
        }
        
    inst = SmapInstance.SmapInstance(data, key='test')
    inst['t'] = a

    # start multiple servers with different options -- an ssl one for
    # authenticated requests, and an insecure one for reading
    SmapHttp.start_server(inst, port=7000, handler=SmapHttp.SslSmapHandler, background=True)
    SmapHttp.start_server(inst, port=8000, background=True)

    idx = 0
    while True:
        inst['data']['0']['sensor']['0'].add(SmapPoint.Reading(time=time.time(),
                                                     value=idx,
                                                     min=None, max=None))
        idx = idx + 1
        inst.push('~/data/0/sensor/0')
        time.sleep(5);
