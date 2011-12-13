"""Driver for HeatX Steam Meter

"""

import time
import struct
from twisted.python import log

import smap.driver as driver
import smap.util as util
from smap.iface.modbustcp.ModbusTCP import ModbusTCP

class HeatX(driver.SmapDriver):
    def setup(self, opts):
        host = opts.get("Host", "10.0.50.118")
        self.rate = int(opts.get("Rate", 20))
        self.modbus = ModbusTCP(host)
        self.add_timeseries('/energy0', 'BTU', data_type="double")
        self.add_timeseries('/energy1', 'BTU', data_type="double")
        self.add_timeseries('/accum0', 'BTU', data_type="double")
        self.add_timeseries('/accum1', 'BTU', data_type="double")
        self.add_timeseries('/volume', 'ga', data_type="double")
        self.add_timeseries('/accum_volume', 'ga', data_type="double")
        self.add_timeseries('/power', 'BTU/hr', data_type="double")
        self.add_timeseries('/vol_flow', 'ga/min', data_type="double")
        self.add_timeseries('/temp_flow', 'f', data_type="double")
        self.add_timeseries('/temp_return', 'f', data_type="double")
        self.add_timeseries('/tdelta', 'f', data_type="double")
        self.set_metadata('/', {
            'Instrument/Manufacturer' : 'Central Station Steam Co.',
            'Instrument/Model' : 'Cadillac HEATX BTU Meter'
            })

    def start(self):
        util.periodicSequentialCall(self.update).start(self.rate)

    def update(self):
        try:
            data = self.modbus.read(25, 36)
        except IOError, e:
            log.err("Exception while reading device: " + str(e))
            return
        if data == None:
            log.err("Failed to read device\n");
            return
        s = ""
        try:
            for i in range(0, len(data), 4):
                s += data[i+1]
                s += data[i+0]
                s += data[i+3]
                s += data[i+2]
            vals = struct.unpack("<18f", s)
        except:
            return

        t = util.now()
        
        self.add("/energy0", t, vals[0])
        self.add("/energy1", t, vals[1])
        self.add("/accum0", t, vals[2])
        self.add("/accum1", t, vals[3])
        self.add("/volume", t, vals[4])
        self.add("/accum_volume", t, vals[5])

        self.add("/power", t, vals[10])
        self.add("/vol_flow", t, vals[12])
        self.add("/temp_flow", t, vals[14])
        self.add("/temp_return", t, vals[15])
        self.add("/tdelta", t, vals[16])
