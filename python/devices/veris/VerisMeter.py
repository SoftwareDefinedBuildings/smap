
import sys
import time
import logging
import struct
import threading


sys.path.append("../../newlib")

import modbus.TCPModbusClient as TCPModbusClient
from SmapPoint import SmapPoint, Formatting, Parameter, Reading
import SmapHttp
import SmapInstance

class VerisMeter:
    all_meters = range(1,43)
    register_map = {
        'current_scale' : (1000, 1041),
        'power_scale'   : (1042, 1083),
        'energy_scale'  : (1084, 1125),
        'kwh'     : (1168, 1251),
        'kwh_fl'  : (2000, 2083),
        'kw'      : (1252, 1293),
        'pf'      : (1294, 1335),
        'current' : (1336, 1377),
        'pkw'     : (1378, 1419),
        'maxkw'   : (1420, 1461),
        'pcurrent': (1462, 1503),
        'maxcurrent' : (1504, 1545),
        'reset'   : (1126, 1167),
        }

    val_clear_kw  = 10203
    val_clear_max = 29877

    def __init__(self, server, port, bus_addr):
        self.server = server
        self.port = port
        self.bus_addr = bus_addr
        self.logger = logging.getLogger('VerisMeter')
        self.last_reading_time = 0.0
        self.last_reset_energy = None
        self.last_reset_time   = 0.0
        self.boot_time = time.time()

    def get_current(self):
        values = self.read_reg_range(self.register_map['current'])
        scales = self.read_reg_range(self.register_map['current_scale'])
        return self.scale_vals(values, scales)

    def get_power(self):
        values = self.read_reg_range(self.register_map['kw'])
        scales = self.read_reg_range(self.register_map['power_scale'])
        return self.scale_vals(values, scales)

    def get_powerfactor(self):
        values = self.read_reg_range(self.register_map['pf'])
        scales = [-3] * len(values)
        return self.scale_vals(values, scales)

    def get_energy_totals(self):
        values_16bit = self.read_reg_range(self.register_map['kwh'])
        scale = self.read_reg_range(self.register_map['energy_scale'])

        values = []
        for i in range(0, len(values_16bit) / 2):
            values.append(((values_16bit[i*2] & 0xffff) << 16) | (values_16bit[i*2+1] & 0xffff))
        return self.scale_vals(values, scale)

    def get_energy(self, current=None):
        if not current:
            current = self.get_energy_totals()
        if not self.last_reset_energy:
            return current

        return map(lambda x,y: x-y, current, self.last_reset_energy)

    def reset_energy(self, vals=None):
        # reset doesn't seem to work reliably -- just remember what it was last time
        if not vals:
            newvals = self.get_energy_totals()
        else:
            newvals = vals
        self.last_reset_time   = time.time()
        self.last_reset_energy = newvals

    def scale_vals(self, vals, scale):
        return map(lambda x,y: x*(10 ** y), vals, scale)

    def read_reg_range(self, (start, end)):
        start -= 1
        end -= 1
        if end < start: 
            self.logger.error("read_reg_range: invalid range: (%i, %i)" % (start,end))
            return None
        self.logger.debug("read_reg_range: %i:%i" % (start, end))

        now = time.time()
        if now - self.last_reading_time < 2:
            time.sleep(2 - (now - self.last_reading_time))

        response = TCPModbusClient.dev_read(self.server, 
                                            self.port,
                                            self.bus_addr, 
                                            start, end - start + 1)

        self.last_reading_time = time.time()
        self.logger.debug("read_reg_range: %i response bytes", response.modbus_val_bytes)

        return [TCPModbusClient.get_val(response.modbus_reg_val, i) 
                for i in range(0, response.modbus_val_bytes / 2)]

# class VerisMeterPoller(threading.Thread):
#     def __init__(self, meter, smapinst, SummationInterval=20):
#         threading.Thread.__init__(self)

#         self.logger = logging.getLogger('VerisMeterPoller')
        
#         self.summation_interval  = SummationInterval
#         self.last_summation     = time.time()

#         self.meter = meter
#         self.smapinst = smapinst
#         self.meter.reset_energy()
#         self.reports = None
        
#     def run(self):
#         while True:
#             try: 
#                 if time.time() - self.last_summation > self.summation_interval:
#                     totals = self.meter.get_energy_totals()
#                     self.metervals['Summation'] = self.meter.get_energy(current=totals)

#                     self.instantaneous['PowerFactor'] = self.meter.get_powerfactor()
#                     self.instantaneous['Power'] = self.meter.get_power()
#                     self.instantaneous['UpdateTime'] = time.time()


#                     print self.metervals
                    
#                     self.meter.reset_energy(vals=totals)

#                     self.last_summation = time.time()
#                     self.logger.info("updated meter values")

#             except IOError, e:
#                 self.logger.error("Failed to update values, ", str(e))
                                   
#             if self.reports:
#                 self.reports.push()

#             now = time.time()
#             sleep_time = min(self.last_summation + self.summation_interval -  now,
#                              self.last_instantaneous + self.instantaneous_interval - now)
#             if sleep_time > 0:
#                 time.sleep(sleep_time)

# class VerisSmapInstance(SmapInstance.SmapInstance):
#     def __init__(self):
#         data = {}
#         for chan in range(1, 43):
#             data[str(chan)] = {
#                 'current' : SmapPoint(Formatting(unit='A', multiplier=None, divisor=None,
#                                                  type='electric', ctype='sensor'),
#                                       Parameter(interval=20, time='second')),
#                 'pf' : SmapPoint(Formatting(unit='pf', multiplier=None, divisor=None,
#                                             type='electric', ctype='sensor'),
#                                  Parameter(interval=20, time='second')),
#                 'real_power' : SmapPoint(Formatting(unit='kW', multiplier=None, divisor=None,
#                                                     type='electric', ctype='sensor'),
#                                          Parameter(interval=20, time='second')),
#                 'real_energy' : SmapPoint(Formatting(unit='pf', multiplier=None, divisor=None,
#                                                      type='electric', ctype='meter'),
#                                           Parameter(interval=20, time='second'))
#                 }
#         SmapInstance.SmapInstance.__init__(self, data, key="verismeter")


# if __name__ == '__main__':
#     import signal
#     signal.signal(signal.SIGINT, signal.SIG_DFL)
    
#     server = sys.argv[1]
#     port = int(sys.argv[2])
#     bus_addr = int(sys.argv[3])

#     v = VerisMeter(server, port, bus_addr)
#     inst = VerisSmapInstance()
#     poller = VerisMeterPoller(v, inst)

#     SmapHttp.smap_server_init(inst)
#     server = SmapHttp.ThreadedHTTPServer(('', 8080), SmapHttp.SmapHandler)

#     poller.start()
#     inst.start()
#     server.serve_forever()

