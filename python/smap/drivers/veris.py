"""Driver for the Veris Industries E30 Panel meter, when connected via
a modbus/ethernet bridge.

Required config parameters:
"Address" : ip or hostname of device
"Port" : tcp port number to connect on
"BusID" : modbus bus address of device

Optional parameters:
"Period" [default 30] : number of seconds between device poll.
"""

import sys
import time
import logging
import struct
import threading

import smap.iface.modbus.TCPModbusClient as TCPModbusClient

from smap.driver import SmapDriver
from smap.loader import SmapLoadError
from smap.util import periodicSequentialCall

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

class VerisDriver(SmapDriver):
    def setup(self, opts):
        if not "Address" in opts or \
           not "Port" in opts or \
           not "BusID" in opts:
            raise SmapLoadError("Veris Driver requires Address, Port, and BusID")
        self.period = opts.get("Period", 30)
        
        for channel in xrange(1, 43):
            self.add_timeseries("/%i/pf" % channel, "pf", data_type="double")
            self.add_timeseries("/%i/power" % channel, "kW", data_type="double")
            self.add_timeseries("/%i/current" % channel, "A", data_type="double")
            self.add_timeseries("/%i/energy" % channel, "kWh", data_type="double")
        self.veris = VerisMeter(opts['Address'], int(opts['Port']), int(opts['BusID']))

    def start(self):
        periodicSequentialCall(self.update).start(self.period)

    def update_field(self, field, data):
        when = int(time.time())
        for i in range(1, 43):
            if i > len(data): return
            self.add("/%i/%s" % (i, field), when, data[i-1])

    def update(self):
        try:
            logging.debug("Updating meter readings")
            current = self.veris.get_current()
            self.update_field('current', current)
            pf = self.veris.get_powerfactor()
            self.update_field('pf', pf)
            power = self.veris.get_power()
            self.update_field('power', power)
            energy = self.veris.get_energy()
            self.update_field('energy', energy)
        except Exception, e:
            logging.error("Exception updating readings: " + str(e))

