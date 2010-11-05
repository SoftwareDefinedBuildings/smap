
import sys
import logging
import time
import pickle
sys.path.append('../../newlib')

import SmapHttp
import SmapInstance
import SmapPoint
import smaplog


if __name__ == '__main__':
    smaplog.start_log()

    data = {
        '0' : {'sensor' :
                   {'0' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='kW',multiplier=None,
                                                                   divisor=None,type='sensor',
                                                                   ctype='sensor'),
                                              SmapPoint.Parameter(interval=5, time='second')) } 
               }
        }
        
    inst = SmapInstance.SmapInstance(data, key='test')
    SmapHttp.start_server(inst, port=8000, background=True)

    idx = 0
    while True:
        inst['data']['0']['sensor']['0'].add(SmapPoint.Reading(time=time.time(),
                                                     value=idx,
                                                     min=None, max=None))
        idx = idx + 1
        inst.push()
        time.sleep(5);
