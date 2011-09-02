#!/usr/bin/env python

"""Utility class for retrieving readings and formatting parameters from
a Dent PowerScout 18 or Dent PowerScout 3 Modbus electric meter.
"""

import sys
import logging
import time
import operator

from twisted.internet import reactor, threads

from smap.driver import SmapDriver
from smap.util import periodicSequentialCall
import smap.core as core
import smap.util as util
import smap.iface.modbus.TCPModbusClient as TCPModbusClient

def e_m(val):
    """energy multiplier"""
    if val == 5: return 10
    elif val >= 6: return 100
    else: return None

def e_d(val):
    """energy divisor"""
    if val == 0: return 10000
    elif val == 1: return 1000
    elif val == 2: return 100
    elif val == 3: return 10
    else: return None

def c_d(val):
    """current divisor"""
    if val == 0: return 100
    elif val >=1 and val <= 3: return 10
    else: return None

def v_d(val):
    """voltage divisor"""
    if val >= 0 and val <= 3: return 10
    else: return None

def add_phase(driver, phase, elt=[]):
    base = '/' + '/'.join(elt + [phase]) + '/'
    if phase in ['AB', 'BC', 'AC']:
        driver.add_timeseries(base + 'volts', 'V', data_type='double')
        return
    
    for name, unit in [('true_energy', 'kWh'), ('reactive_energy', 'kVARh'),
                       ('apparent_energy', 'kVAh'), ('true_power', 'kW'),
                       ('reactive_power', 'kVAR'), ('apparent_power', 'kVA'),
                       ('displacement_pf', 'PF'), ('apparent_pf', 'PF'),
                       ('current', 'A'), ('line_frequency', 'HZ'),
                       ('phase-neutral_voltage', 'V')]:
        if name == 'line_frequency' and phase in ['A', 'B', 'C']:
            continue
        if name == 'phase-neutral_voltage' and phase in ['ABC']:
            continue
        driver.add_timeseries(base + name, unit, data_type='double')

def add_phases(driver, elt=[]):
    map(lambda p: add_phase(driver, p, elt=elt),
        ['A', 'B', 'C', 'ABC', 'AB', 'BC', 'AC'])
        

class Dent18(SmapDriver):
    def setup(self, opts):
        # hostname, port tuple
        self.serverloc = (opts['Address'], int(opts.get('Port', 4660)))
        # base modbus address
        self.base_addr = int(opts.get('ModbusBase', 1))
        # min time between device reads
        self.limit = float(opts.get('Limit', 1.5))
        # how often to take a new reading
        self.rate = int(opts.get('Rate', 20))

        self.scale_register = 4300
        self.scalar = None
        self.last_read = None
        self.elt_scales = [('elt-A', None), ('elt-B', None),
                           ('elt-C', None), ('elt-D', None),
                           ('elt-E', None), ('elt-F', None)]
        
        map(lambda elt: add_phases(self, elt=[elt[0]]),
            self.elt_scales)

        # add a bunch of tags
        self.set_metadata('/', {
            'Extra/Driver' : 'smap.drivers.dent.Dent18', 
            'Extra/SystemType' : 'Electrical',
            'Instrument/Manufacturer' : 'Dent Industries',
            'Instrument/Model' : 'PowerScout 18',
            'Instrument/SamplingPeriod' : str(self.rate),
            })
        for elt in map(operator.itemgetter(0), self.elt_scales):
            self.set_metadata('/' + elt, {
                'Extra/DentElement' : elt })
            for ph in ['A', 'B', 'C', 'ABC', 'AB', 'BC', 'AC']:
                self.set_metadata('/%s/%s' % (elt, ph), {
                    'Extra/Phase' : ph
                    })
        
    def start(self):
        threads.deferToThread(self.blocking_startup)
        
    def blocking_startup(self):
        # read the scale register from the dent
        for i in range(0, len(self.elt_scales)):
            for attempt in xrange(0, 5):
                try:
                    scale = self.read_scale(self.base_addr + i)
                except IOError:
                    scale = None
                if scale != None: break
            if scale == None:
                raise core.SmapException("Could not read sale from dent: cannot proceed (%s)" %
                                         (str(self.serverloc)))
            self.elt_scales[i] = self.elt_scales[i][0], scale
        print self.elt_scales
        reactor.callInThread(self.final_startup)

    def final_startup(self):
        periodicSequentialCall(self.update_all).start(self.rate)
            

    def read_scale(self, modbus_addr):
        """Read the scale register on a dent"""
        self.modbus_addr = modbus_addr
        response = self.dev_read(self.scale_register, 3)
        data = [(TCPModbusClient.get_val(response.modbus_reg_val, i) & 0xffff)
                for i in range(0, response.modbus_val_bytes / 2)]

        if len(data) != 3:
            return None

        # return the scaling indicator expressed by the dent
        return data[1]

    def to_word(self, seg):
        return seg[0] | (seg[1] << 16)

    def dev_sleep(self):
        now = time.time()
        if not self.last_read or now - self.last_read > self.limit:
            self.last_read = now
        else:
            time.sleep(self.limit - now + self.last_read)
            self.last_read = time.time()
                
    def dev_read(self, *args):
        try:
            self.dev_sleep()
            return TCPModbusClient.dev_read(self.serverloc[0], self.serverloc[1],self.modbus_addr,*args)
        except:
            return None

    def dev_write(self, *args):
        try:
            self.dev_sleep()
            return TCPModbusClient.dev_write(self.serverloc[0], self.serverloc[1],self.modbus_addr,*args)
        except:
            return None

    def update_all(self):
        for i in range(0, len(self.elt_scales)):
            self.update(self.elt_scales[i][0], self.elt_scales[i][1], self.base_addr + i)

    def update(self, elt, scale, modbus_addr):
        self.modbus_addr = modbus_addr
        response = self.dev_read(4000, 70)
        time.sleep(2)
        data = [(TCPModbusClient.get_val(response.modbus_reg_val, i) & 0xffff)
                for i in range(0, response.modbus_val_bytes / 2)]
        if len(data) != 70:
            print "Short read from", self.serverloc,  modbus_addr
            return

        reading_time = int(time.time())
        base = '/%s' % elt
        self.add(base + '/ABC/true_energy', reading_time,
                 float(self.to_word(data[0:2])) / e_d(scale))
        self.add(base + '/ABC/reactive_energy', reading_time,
                 float(self.to_word(data[7:9])) / e_d(scale))
        self.add(base + '/ABC/apparent_energy', reading_time,
                 float(self.to_word(data[10:12])) / e_d(scale))
        self.add(base + '/ABC/true_power', reading_time,
                 float(data[2]) / e_d(scale))
        # min=data[6], max=data[5]))
        self.add(base + '/ABC/reactive_power', reading_time,
                 float(data[9]) / e_d(scale))
        self.add(base + '/ABC/apparent_power', reading_time,
                 float(data[12]) / e_d(scale))
        self.add(base + '/ABC/displacement_pf', reading_time,
                 float(data[13]) / 100)
        self.add(base + '/ABC/apparent_pf', reading_time,
                 float(data[14]) / 100)
        self.add(base + '/ABC/current', reading_time,
                 float(data[15]) / c_d(scale))
        # line frequency divisor is not in the datasheet, but called Dent to verify 3-26-2010
        self.add(base + '/ABC/line_frequency', reading_time,
                 float(data[21]) / 100)
        self.add(base + '/AB/volts', reading_time,
                 float(data[18]) / v_d(scale))
        self.add(base + '/BC/volts',  reading_time,
                 float(data[19]) / v_d(scale))
        self.add(base + '/AC/volts', reading_time,
                 float(data[20]) / v_d(scale))

        def w_i(d, i):
            return d[i] | (d[i+1] << 16)

        for (i,v) in [(0,'A'), (1,'B'), (2,'C')]:
            base = '/%s/%s/' % (elt, v)
            self.add(base + 'true_energy', reading_time,
                     float(w_i(data, 22+(i*2))) / e_d(scale))
            self.add(base + 'reactive_energy', reading_time, 
                     float(w_i(data, 31+(i*2))) / e_d(scale))
            self.add(base + 'apparent_energy', reading_time, 
                     float(w_i(data, 40+(i*2))) / e_d(scale))
            self.add(base + 'true_power', reading_time, 
                     float(data[28+i]) / e_d(scale))
            self.add(base + 'reactive_power', reading_time, 
                     float(data[37+i]) / e_d(scale))
            self.add(base + 'apparent_power', reading_time, 
                     float(data[46+i]) / e_d(scale))
            self.add(base + 'displacement_pf', reading_time, 
                     float(data[49+i]) / 100)
            self.add(base + 'apparent_pf', reading_time, 
                     float(data[52+i]) / 100)
            self.add(base + 'current', reading_time, 
                     float(data[55+i]) / c_d(scale))
            self.add(base + 'phase-neutral_voltage', reading_time, 
                     float(data[58+i]) / v_d(scale))
