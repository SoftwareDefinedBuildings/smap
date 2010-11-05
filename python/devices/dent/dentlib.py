#!/usr/bin/env python

"""Utility class for retrieving readings and formatting parameters from
a Dent PowerScout 18 or Dent PowerScout 3 Modbus electric meter.
"""

import sys
import logging
import time
import signal
import pickle
import threading

import SmapPoint

import modbus.TCPModbusClient as TCPModbusClient

def e_m(val):
    if val == 5: return 10
    elif val >= 6: return 100
    else: return None

def e_d(val):
    if val == 0: return 10000
    elif val == 1: return 1000
    elif val == 2: return 100
    elif val == 3: return 10
    else: return None

def c_d(val):
    if val == 0: return 100
    elif val >=1 and val <= 3: return 10
    else: return None

def v_d(val):
    if val >= 0 and val <= 3: return 10
    else: return None

def try_add(d, key, fmt):
    if d.has_key(key):
        d[key].formatting = fmt

class DentUpdater:
    def __init__(self, serverloc, limit=1.5, type='dent18'):
        self.serverloc = serverloc
        self.scalar = None
        self.last_read = None
        self.limit=limit

        if type.lower() == 'dent18':
            self.scale_register = 4300
        elif type.lower() == 'dent3':
            self.scale_register = 4602
        else:
            raise ValueError("Invalid dent type: options are 'dent18' and 'dent3'")

    def set_scalar(self, inst, val):
        for point,v1 in inst['data'].iteritems():
            for ctype,v2 in v1.iteritems():
                try_add(v2, 'true_energy',
                        SmapPoint.Formatting(unit='kWh', multiplier=e_m(val), divisor=e_d(val),
                                             type='electric', ctype='meter'))
                try_add(v2, 'reactive_energy',
                        SmapPoint.Formatting(unit='kVARh', multiplier=e_m(val), divisor=e_d(val),
                                             type='electric', ctype='meter'))
                try_add(v2, 'apparent_energy',
                        SmapPoint.Formatting(unit='kVAh', multiplier=e_m(val), divisor=e_d(val),
                                             type='electric', ctype='meter'))
                try_add(v2, 'true_power',
                        SmapPoint.Formatting(unit='kW', multiplier=e_m(val), divisor=e_d(val),
                                             type='electric', ctype='sensor'))
                try_add(v2, 'reactive_power',
                        SmapPoint.Formatting(unit='kVAR', multiplier=e_m(val), divisor=e_d(val),
                                             type='electric', ctype='sensor'))
                try_add(v2, 'apparent_power',
                        SmapPoint.Formatting(unit='kVA', multiplier=e_m(val), divisor=e_d(val),
                                             type='electric', ctype='sensor'))
                try_add(v2, 'displacement_pf',
                        SmapPoint.Formatting(unit='PF', multiplier=None, divisor=100,
                                             type='electric', ctype='sensor'))
                try_add(v2, 'apparent_pf',
                        SmapPoint.Formatting(unit='PF', multiplier=None, divisor=100,
                                             type='electric', ctype='sensor'))
                try_add(v2, 'current',
                        SmapPoint.Formatting(unit='A', multiplier=None, divisor=c_d(val),
                                             type='electric', ctype='sensor'))
                # line frequency divisor is not in the datasheet, but called Dent to verify 3-26-2010
                try_add(v2, 'line_frequency',
                        SmapPoint.Formatting(unit='HZ', multiplier=None, divisor=100,
                                             type='electric', ctype='sensor'))
                try_add(v2, 'phase-neutral_voltage',
                        SmapPoint.Formatting(unit='V', multiplier=None, divisor=v_d(val),
                                             type='electric', ctype='sensor'))
                try_add(v2, 'volts',
                        SmapPoint.Formatting(unit='V', multiplier=None, divisor=v_d(val),
                                             type='electric', ctype='sensor'))

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

    def update(self, inst, modbus_addr, update_meters=True):
        logging.debug("updating readings")
        self.modbus_addr = modbus_addr
        response = self.dev_read(4000, 70)

        data = [(TCPModbusClient.get_val(response.modbus_reg_val, i) & 0xffff)
                for i in range(0, response.modbus_val_bytes / 2)]

        if len(data) != 70:
            return

        self.reading_time = time.time()
        reading_time = self.reading_time
        metering_time = self.reading_time

        if update_meters:
            self.last_meter_update = self.reading_time
            
            inst['data']['ABC']['meter']['true_energy'].add( \
                    SmapPoint.Reading(time=metering_time,
                                      value=self.to_word(data[0:2]),
                                      min=None, max=None))
            inst['data']['ABC']['meter']['reactive_energy'].add( \
                    SmapPoint.Reading(time=metering_time,
                                            value=self.to_word(data[7:9]),
                                            min=None, max=None))
            inst['data']['ABC']['meter']['apparent_energy'].add( \
                    SmapPoint.Reading(time=metering_time,
                                            value=self.to_word(data[10:12]),
                                            min=None, max=None))

        inst['data']['ABC']['sensor']['true_power'].add( \
                    SmapPoint.Reading(time=reading_time,
                                            value=data[2],
                                            min=data[6], max=data[5]))
        inst['data']['ABC']['sensor']['reactive_power'].add( \
                    SmapPoint.Reading(time=reading_time,
                                            value=data[9],
                                            min=None, max=None))
        inst['data']['ABC']['sensor']['apparent_power'].add( \
                    SmapPoint.Reading(time=reading_time,
                                            value=data[12],
                                            min=None, max=None))
        inst['data']['ABC']['sensor']['displacement_pf'].add( \
                    SmapPoint.Reading(time=reading_time,
                                            value=data[13],
                                            min=None, max=None))
        inst['data']['ABC']['sensor']['apparent_pf'].add( \
                    SmapPoint.Reading(time=reading_time,
                                        value=data[14],
                                            min=None, max=None))
        inst['data']['ABC']['sensor']['current'].add( \
                    SmapPoint.Reading(time=reading_time,
                                            value=data[15],
                                            min=None, max=None))
        inst['data']['ABC']['sensor']['line_frequency'].add( \
                    SmapPoint.Reading(time=reading_time,
                                            value=data[21],
                                            min=None, max=None))
        inst['data']['AB']['sensor']['volts'].add( \
                    SmapPoint.Reading(time=reading_time,
                                            value=data[18],
                                            min=None, max=None))
        inst['data']['BC']['sensor']['volts'].add( \
                    SmapPoint.Reading(time=reading_time,
                                            value=data[19],
                                            min=None, max=None))
        inst['data']['AC']['sensor']['volts'].add( \
                    SmapPoint.Reading(time=reading_time,
                                            value=data[20],
                                            min=None, max=None))

        def w_i(d, i):
            return d[i] | (d[i+1] << 16)

        for (i,v) in [(0,'A'), (1,'B'), (2,'C')]:
            if update_meters:
                inst['data'][v]['meter']['true_energy'].add( \
                        SmapPoint.Reading(time=reading_time,
                                          value=w_i(data, 22+(i*2)),
                                          min=None, max=None))
                inst['data'][v]['meter']['reactive_energy'].add( \
                        SmapPoint.Reading(time=reading_time,
                                          value=w_i(data, 31+(i*2)),
                                          min=None, max=None))
                inst['data'][v]['meter']['apparent_energy'].add( \
                        SmapPoint.Reading(time=reading_time,
                                          value=w_i(data, 40+(i*2)),
                                          min=None, max=None))
                
            inst['data'][v]['sensor']['true_power'].add( \
                        SmapPoint.Reading(time=reading_time,
                                          value=data[28+i],
                                          min=None, max=None))
            inst['data'][v]['sensor']['reactive_power'].add( \
                        SmapPoint.Reading(time=reading_time,
                                          value=data[37+i],
                                          min=None, max=None))
            inst['data'][v]['sensor']['apparent_power'].add( \
                        SmapPoint.Reading(time=reading_time,
                                          value=data[46+i],
                                          min=None, max=None))
            inst['data'][v]['sensor']['displacement_pf'].add( \
                        SmapPoint.Reading(time=reading_time,
                                          value=data[49+i],
                                          min=None, max=None))
            inst['data'][v]['sensor']['apparent_pf'].add( \
                        SmapPoint.Reading(time=reading_time,
                                          value=data[52+i],
                                          min=None, max=None))
            inst['data'][v]['sensor']['current'].add( \
                        SmapPoint.Reading(time=reading_time,
                                          value=data[55+i],
                                          min=None, max=None))
            inst['data'][v]['sensor']['phase-neutral_voltage'].add( \
                        SmapPoint.Reading(time=reading_time,
                                          value=data[58+i],
                                          min=None, max=None))

        response = self.dev_read(self.scale_register, 3)
        data = [(TCPModbusClient.get_val(response.modbus_reg_val, i) & 0xffff)
                for i in range(0, response.modbus_val_bytes / 2)]

        if len(data) != 3:
            return

        # update the formatting objects to reflect the scaling values
        self.set_scalar(inst, data[1])

