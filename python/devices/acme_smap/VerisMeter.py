
import sys
import time
import logging
import struct
import threading

import TCPModbusClient

class VerisMeter:
    all_meters = range(1,43)
    register_map = {
        'current_scale' : (1000, 1041),
        'power_scale'   : (1042, 1083),
#        'energy_scale'  : (1084, 1125),
        'energy_scale'  : (1084, 1124),
#        'kwh'     : (1168, 1251),
        'kwh'     : (1168, 1249),
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

    def get_energy(self):
        values_long = self.read_reg_range(self.register_map['kwh_fl'])
        # scales      = self.read_reg_range(self.register_map['energy_scale'])

        values = []
        for i in range(0, len(values_long) / 2):
            s =  chr((values_long[i*2] & 0xff)) + chr((values_long[i*2] >> 8) & 0xff) 
            s += chr((values_long[i*2+1] & 0xff)) + chr((values_long[i*2+1] >> 8) & 0xff) 
            (i, ) = struct.unpack("f", s)
            values.append(i)

        energies = values
        if not self.last_reset_energy:
            return energies

        return map(lambda x,y: x-y, energies, self.last_reset_energy)

    def reset_energy(self, vals=None):
        # reset doesn't seem to work reliably -- just remember what it was last time
        if not vals:
            self.last_reset_energy = self.get_energy()
        else:
            self.last_reset_energy = vals
        self.last_reset_time   = time.time()

    def scale_vals(self, vals, scale):
        return map(lambda x,y: x*(10 ** y), vals, scale)

    def read_reg_range(self, (start, end)):
        if end < start: 
            self.logger.error("read_reg_range: invalid range: (%i, %i)" % (start,end))
            return None
        self.logger.debug("read_reg_range: %i:%i" % (start, end))

        now = time.time()
        if now - self.last_reading_time < 1:
            time.sleep(1 - (now - self.last_reading_time))

        response = TCPModbusClient.dev_read(self.server, 
                                            self.port,
                                            self.bus_addr, 
                                            start, end - start + 1)

        self.last_reading_time = time.time()
        self.logger.debug("read_reg_range: %i response bytes", response.modbus_val_bytes)

        return [TCPModbusClient.get_val(response.modbus_reg_val, i) 
                for i in range(0, response.modbus_val_bytes / 2)]

class VerisMeterPoller(threading.Thread):
    def __init__(self, meter, SummationInterval=60, InstantaneousInterval=15):
        threading.Thread.__init__(self)

        self.logger = logging.getLogger('VerisMeterPoller')
        
        self.summation_interval  = SummationInterval
        self.instantaneous_interval = InstantaneousInterval

        self.last_summation     = time.time()
        self.last_instantaneous = 0

        self.meter = meter
        self.instantaneous  = { 
            'PowerFactor' : None,
            'Power'       : None,
            'UpdateTime'  : None }
        self.metervals = {
            'Summation'   : [0.0] * 42
            }
        self.changeHandler = None

        self.meter.reset_energy()
        
    def addChangeHandler(self, handler):
        self.changeHandler = handler
        
    def run(self):
        while True:
            if time.time() - self.last_summation > self.summation_interval:
                self.metervals['Summation'] = self.meter.get_energy()
                self.meter.reset_energy(self.metervals['Summation'])
                self.last_summation = time.time()
                if self.changeHandler:
                    self.changeHandler()
                self.logger.debug("updated meter values")

            if time.time() - self.last_instantaneous > self.instantaneous_interval:
                self.instantaneous['PowerFactor'] = self.meter.get_powerfactor()
                self.instantaneous['Power'] = self.meter.get_power()
                self.instantaneous['UpdateTime'] = time.time()
                self.last_instantaneous = self.instantaneous['UpdateTime']
                self.logger.debug("updated instantaneous values")

            now = time.time()
            sleep_time = min(self.last_summation + self.summation_interval -  now,
                             self.last_instantaneous + self.instantaneous_interval - now)
            if sleep_time > 0:
                time.sleep(sleep_time)
                
                                        

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    server = sys.argv[1]
    port = int(sys.argv[2])
    bus_addr = int(sys.argv[3])

    v = VerisMeter(server, port, bus_addr)
    s = VerisMeterPoller(v)

    s.run()
#     print v.get_power()
#     print v.get_current()
#     v.reset_energy()
#     time.sleep(60)
#     print "energy:", v.get_energy()
