"""sMAP proxy for the Omega iSeries stream flow meter.
"""
import sys
import logging
import time
import socket
sys.path.append('../../newlib')

import SmapHttp
import SmapInstance
import SmapPoint
import smaplog
import conf

def read(host="10.0.50.119", cmd="*01X01", port=1000):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(1)
            s.connect((host, port))
            s.send(cmd + "\r")
            reply = s.recv(1024)
            s.close()
        except IOError, e:
            return None
        else:
            if reply.startswith(cmd[1:]):
                return float(reply[len(cmd) - 1:-1])
                

if __name__ == '__main__':
    INTERVAL=30
    smaplog.start_log()

    data = {
        'steam' : {'sensor' :
                   {'0' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='ga/min',multiplier=None,
                                                                   divisor=None,type='steam',
                                                                   ctype='sensor'),
                                              SmapPoint.Parameter(interval=INTERVAL, time='second')) },
                   'meter' :
                   {'0' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='ga', multiplier=None,
                                                                   divisor=None,type='steam',
                                                                   ctype='meter'),
                                              SmapPoint.Parameter(interval=INTERVAL, time='second')) }
               } 
        }
        
    inst = SmapInstance.SmapInstance(data, key="iseries-steam")
    SmapHttp.start_server(inst, background=True, port=conf.SMAP_PORT)

    last_time = None
    last_add = 0
    accum = 0
    while True:
        val = read()
        this_time = time.time()

        if val == None:
            time.sleep(0.5)
            logging.warn("Failed to update reading")
            continue
        
        if last_time:
            accum += (last_time[1] + val) * ((this_time - last_time[0]) / 60) * 0.5


        if this_time - last_add > INTERVAL:
            inst['data']['steam']['sensor']['0'].add(SmapPoint.Reading(time=this_time,
                                                                       value=val,
                                                                       min=None, max=None))
            inst['data']['steam']['meter']['0'].add(SmapPoint.Reading(time=this_time,
                                                                      value=accum,
                                                                      min=None, max=None))
            inst.push()
            last_add = this_time
            
        last_time = (this_time, val)
        time.sleep(1)
