"""
Copyright (c) 2011, 2012, Regents of the University of California
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions 
are met:

 - Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
 - Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the
   distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL 
THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED 
OF THE POSSIBILITY OF SUCH DAMAGE.
"""
"""
@author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
"""
"""Driver for the Power Standards Lab pQube meter.  

The driver scrapes the html spit out by the meter, making it dependent
on a particular interface.

Config options:
Address : url of the meter
Rate [default 10] : polling period

"""


import sys
import logging
import time
import calendar
import threading
import urllib2
import httplib
import urlparse
import re
import operator
import struct

from twisted.python import log

from smap.driver import SmapDriver
from smap.drivers import modbus
from smap.drivers.modbus import ModbusRegister as R
from smap.util import periodicSequentialCall

urllib2.install_opener(urllib2.build_opener())

def p(val):
    return float(val[0])
def kwh_mwh_parser(val):
    if val[1] == 'kwh':
        return float(val[0])
    else:
        return float(val[0]) * 1000

PQUBE_POINTS = [
    ('L1-N', r'^(\d+\.\d+)', 'A', 'phase-neutral_voltage', 'V', p), 
    ('L2-N', r'^(\d+\.\d+)', 'B', 'phase-neutral_voltage', 'V', p), 
    ('L3-N', r'^(\d+\.\d+)', 'C', 'phase-neutral_voltage', 'V', p), 

    ('L1 Amp', r'^(\d+\.\d+)', 'A', 'current', 'A', p), 
    ('L2 Amp', r'^(\d+\.\d+)', 'B', 'current', 'A', p), 
    ('L3 Amp', r'^(\d+\.\d+)', 'C', 'current', 'A', p), 

#     ('L1-N Voltage Fundamental', r'^(\d+\.\d+)', 'A', 'a-n fundamental voltage', p),
#     ('L1-N Voltage Fundamental', r'^(\d+\.\d+)', 'A', 'a-n fundamental phase', p),
#     ('L2-N Voltage Fundamental', r'^(\d+\.\d+)', 'B', 'a-n fundamental voltage', p),
#     ('L2-N Voltage Fundamental', r'^(\d+\.\d+)', 'B', 'a-n fundamental phase', p),
#     ('L3-N Voltage Fundamental', r'^(\d+\.\d+)', 'C', 'a-n fundamental voltage', p),
#     ('L3-N Voltage Fundamental', r'^(\d+\.\d+)', 'C', 'a-n fundamental phase', p),

    ('Frequency', r'^(\d+\.\d+)', 'ABC', 'line_frequency', 'Hz', p), 
    ('Voltage THD', r'^(\d+\.\d+)', 'ABC', 'voltage_thd', 'pct', p), 
    ('Current TDD', r'^(\d+\.\d+)', 'ABC', 'current_tdd', 'pct', p), 

    ('L1-L2', r'^(\d+\.\d+)', 'AB', 'volts', 'V', p), 
    ('L2-L3', r'^(\d+\.\d+)', 'BC', 'volts', 'V', p), 
    ('L3-L1', r'^(\d+\.\d+)', 'AC', 'volts', 'V', p), 

    ('Power', r'^(\d+\.\d+)', 'ABC', 'true_power', 'kW', p), 
    ('Apparent Power', r'^(\d+\.\d+)', 'ABC', 'apparent_power', 'kVA', p), 
    ('Reactive Power', r'^(\d+\.\d+)', 'ABC', 'reactive_power', 'kVAR', p), 
    ('True Power Factor', r'^(\d+\.\d+)', 'ABC', 'pf', 'PF', p), 

    # meters
    ('Energy', r'^(\d+\.\d+)(kwh|mwh)', 'ABC', 'true_energy', 'kWh', kwh_mwh_parser),
    ('Apparent Energy', r'^(\d+\.\d+)', 'ABC', 'apparent_energy', 'kVAh', p), 
    ]


class PQube(SmapDriver):
    def setup(self, opts):
        self.serverloc = opts['Address']
        self.rate = int(opts.get('Rate', 10))
        for (field, regexp, phase, channel, fmt, vparser) in PQUBE_POINTS:
            self.add_timeseries('/%s/%s' % (phase, channel), fmt, data_type="double")
            self.set_metadata('/%s' % phase, {
                'Extra/Phase' : phase})

        self.set_metadata('/', {
            'Instrument/Manufacturer' : 'Power Standards Laboratory',
            'Instrument/SamplingPeriod' : str(self.rate),
            'Extra/Driver' : 'smap.drivers.pqube.PQube',
            })

    def start(self):
        periodicSequentialCall(self.update).start(self.rate)
        
    def update(self):
        logging.debug("Updating " + self.serverloc)
        try:
            fp = urllib2.urlopen(self.serverloc + '/Meters.htm', timeout=15)
            html = fp.read()
        except IOError, e:
            logging.error("IOError while reading pqube: url: %s exception: %s" % 
                          (self.serverloc, str(e)))
            return
        except httplib.HTTPException, e:
            logging.error("HTTP exception reading pqube: url: %s exception: %s" % 
                          (self.serverloc, str(e)))
            return

        reading_time = int(time.time())
        # this pulls out a list of all the channel-reading pairs
        data = re.findall('<td.*? class="channel">(.*?)</td>.*?<td.*?>(.*?)</td>',
                          html.lower())
        data = [(re.sub('<.*>', '', k), v) for (k,v) in data]
        data_map = {}
        data_map.update(data)

        for (field, regexp, phase, channel, fmt, vparser) in PQUBE_POINTS:
            reading = data_map.get(field.lower())
            if not reading: 
                logging.warn(field + " not found in doc")
                continue
            match = re.search(regexp, reading)
            if not match: 
                logging.warn("reading conversion failed: " + reading)
                continue

            self.add('/%s/%s' % (phase, channel), reading_time, vparser(match.groups(0)))


class PQubeModbus(modbus.ModbusDriver):
    # modbus registers
    # reg number : (description, phase, channelname, units)
    BASE = 7000
    
    REGISTERS = {
        0 : R('/A/phase-earth_voltage', 'V', modbus.float), 
        2 : R('/B/phase-earth_voltage', 'V', modbus.float), 
        4 : R('/C/phase-earth_voltage', 'V', modbus.float), 

        8 : R('/A/phase-neutral_voltage', 'V', modbus.float), 
        10 : R('/B/phase-neutral_voltage', 'V', modbus.float), 
        12 : R('/C/phase-neutral_voltage', 'V', modbus.float), 

        28 : R('/A/current', 'A', modbus.float, 'L1 Amp'), 
        30 : R('/B/current', 'A', modbus.float, 'L2 Amp'), 
        32 : R('/C/current', 'A', modbus.float, 'L3 Amp'), 

        26 : R('/ABC/line_frequency', 'Hz', modbus.float, 'Frequency'), 
        64 : R('/ABC/voltage_thd', 'pct', modbus.float, 'Voltage THD'), 
        66 : R('/ABC/current_tdd', 'pct', modbus.float, 'Current TDD'), 

        14 : R('/AB/volts', 'V', modbus.float, 'L1-L2'), 
        16 : R('/BC/volts', 'V', modbus.float, 'L2-L3'), 
        18 : R('/AC/volts', 'V', modbus.float, 'L3-L1'), 

        36 : R('/ABC/true_power', 'W', modbus.float, 'Power'), 
        38 : R('/ABC/apparent_power', 'VA', modbus.float, 'Apparent Power'), 
        80 : R('/ABC/reactive_power', 'VAR', modbus.float, 'Reactive Power'), 
        82 : R('/ABC/pf', 'PF', modbus.float, 'True Power Factor'), 

        # meters
        60 : R('/ABC/true_energy', 'Wh', modbus.float),
        62 : R('/ABC/apparent_energy', 'VAh', modbus.float),
        }

    METADATA = {
            'Instrument/Manufacturer' : 'Power Standards Laboratory',
            'Extra/Driver' : 'smap.drivers.pqube.PQube',
            }

