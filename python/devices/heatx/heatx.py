"""sMAP gateway for a HeatX Cadillac chilled water meter communicating
of ModbusTCP.
"""

import sys
import time
import struct
import logging

sys.path.append("../../newlib")
from modbustcp.ModbusTCP import ModbusTCP
import smaplog
import SmapHttp
import SmapInstance
import SmapPoint
import util
import conf

param = SmapPoint.Parameter(conf.RATE, 'second')
heatx = {
    'meter' : {
      'energy0' : SmapPoint.SmapPoint(formatting=SmapPoint.Formatting('BTU', None, None,
                                                                      'water', 'meter'),
                                      parameter=param),
      'energy1' : SmapPoint.SmapPoint(formatting=SmapPoint.Formatting('BTU', None, None,
                                                                      'water', 'meter'),
                                      parameter=param),
      'accum0'  : SmapPoint.SmapPoint(formatting=SmapPoint.Formatting('BTU', None, None,
                                                                      'water', 'meter'),
                                      parameter=param),
      'accum1'  : SmapPoint.SmapPoint(formatting=SmapPoint.Formatting('BTU', None, None,
                                                                      'water', 'meter'),
                                      parameter=param),
      'volume' : SmapPoint.SmapPoint(formatting=SmapPoint.Formatting('ga', None, None,
                                                                     'water', 'meter'),
                                     parameter=param),
      'accum_volume' : SmapPoint.SmapPoint(formatting=SmapPoint.Formatting('ga', None, None,
                                                                           'water', 'meter'),
                                           parameter=param)}, 
    'sensor' : {
      'power'  : SmapPoint.SmapPoint(formatting=SmapPoint.Formatting('BTU/hr', None, None,
                                                                     'water', 'sensor'),
                                     parameter=param),
      'vol_flow' : SmapPoint.SmapPoint(formatting=SmapPoint.Formatting('ga/min', None, None,
                                                                       'water', 'sensor'),
                                       parameter=param),
      'temp_flow' : SmapPoint.SmapPoint(formatting=SmapPoint.Formatting('f', None, None,
                                                                        'water', 'sensor'),
                                        parameter=param),
      'temp_return' : SmapPoint.SmapPoint(formatting=SmapPoint.Formatting('f', None, None,
                                                                          'water', 'sensor'),
                                          parameter=param),
      'tdelta' : SmapPoint.SmapPoint(formatting=SmapPoint.Formatting('f', None, None,
                                                                     'water', 'sensor'),
                                     parameter=param)}
    }

class HeatX:
    def __init__(self, host, instance):
        self.modbus = ModbusTCP(host)
        self.inst = instance

    def update(self):
        try:
            data = self.modbus.read(25, 36)
        except IOError, e:
            logging.error("Exception while reading device: " + str(e))
            return
        if data == None:
            logging.warn("Failed to read device\n");
            return
        s = ""
        for i in range(0, len(data), 4):
            s += data[i+1]
            s += data[i+0]
            s += data[i+3]
            s += data[i+2]
        try:
            vals = struct.unpack("<18f", s)
        except:
            return

        t = int(time.time())
        self.inst['data']['heatx']['meter']["energy0"].add(SmapPoint.Reading(t, vals[0], None, None))
        self.inst['data']['heatx']['meter']["energy1"].add(SmapPoint.Reading(t, vals[1], None, None))
        self.inst['data']['heatx']['meter']["accum0"].add(SmapPoint.Reading(t, vals[2], None, None))
        self.inst['data']['heatx']['meter']["accum1"].add(SmapPoint.Reading(t, vals[3], None, None))
        self.inst['data']['heatx']['meter']["volume"].add(SmapPoint.Reading(t, vals[4], None, None))
        self.inst['data']['heatx']['meter']["accum_volume"].add(SmapPoint.Reading(t, vals[5], None, None))

        self.inst['data']['heatx']['sensor']["power"].add(SmapPoint.Reading(t, vals[10], None, vals[11]))
        self.inst['data']['heatx']['sensor']["vol_flow"].add(SmapPoint.Reading(t, vals[12], None, None))
        self.inst['data']['heatx']['sensor']["temp_flow"].add(SmapPoint.Reading(t, vals[14], None, None))
        self.inst['data']['heatx']['sensor']["temp_return"].add(SmapPoint.Reading(t, vals[15], None, None))
        self.inst['data']['heatx']['sensor']["tdelta"].add(SmapPoint.Reading(t, vals[16], None, None))
        self.inst.push()

if __name__ == '__main__':
    SmapHttp.smap_server_init()    
    inst = SmapInstance.SmapInstance({'heatx' : heatx}, key="heatx")
    
    updater = HeatX(conf.HEATX_DEV, inst)
    timer = util.RateTimer(conf.RATE, lambda: updater.update())
    timer.start()

    SmapHttp.start_server(inst, port=conf.SMAP_PORT)
