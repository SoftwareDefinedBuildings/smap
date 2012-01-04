#!/usr/bin/env python
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
import signal

from smap.driver import SmapDriver
from smap.util import periodicSequentialCall

urllib2.install_opener(urllib2.build_opener())

PQUBE_POINTS = [
    ('L1-N', r'^(\d+\.\d+)', 'A', 'phase-neutral_voltage', 'V'), #ultiplier=1, divisor=1,
    ('L2-N', r'^(\d+\.\d+)', 'B', 'phase-neutral_voltage', 'V'), #ultiplier=1, divisor=1,
    ('L3-N', r'^(\d+\.\d+)', 'C', 'phase-neutral_voltage', 'V'), #ultiplier=1, divisor=1,

    ('L1 Amp', r'^(\d+\.\d+)', 'A', 'current', 'A'), #ultiplier=1, divisor=1,
    ('L2 Amp', r'^(\d+\.\d+)', 'B', 'current', 'A'), #ultiplier=1, divisor=1,
    ('L3 Amp', r'^(\d+\.\d+)', 'C', 'current', 'A'), #ultiplier=1, divisor=1,

#     ('L1-N Voltage Fundamental', r'^(\d+\.\d+)', 'A', 'a-n fundamental voltage'),
#     ('L1-N Voltage Fundamental', r'^(\d+\.\d+)', 'A', 'a-n fundamental phase'),
#     ('L2-N Voltage Fundamental', r'^(\d+\.\d+)', 'B', 'a-n fundamental voltage'),
#     ('L2-N Voltage Fundamental', r'^(\d+\.\d+)', 'B', 'a-n fundamental phase'),
#     ('L3-N Voltage Fundamental', r'^(\d+\.\d+)', 'C', 'a-n fundamental voltage'),
#     ('L3-N Voltage Fundamental', r'^(\d+\.\d+)', 'C', 'a-n fundamental phase'),

    ('Frequency', r'^(\d+\.\d+)', 'ABC', 'line_frequency', 'Hz'), #ultiplier=1, divisor=1,
    ('Voltage THD', r'^(\d+\.\d+)', 'ABC', 'voltage_thd', 'pct'), #ultiplier=1, divisor=1,
    ('Current TDD', r'^(\d+\.\d+)', 'ABC', 'current_tdd', 'pct'), #ultiplier=1, divisor=1,

    ('L1-L2', r'^(\d+\.\d+)', 'AB', 'volts', 'V'), #ultiplier=1, divisor=1,
    ('L2-L3', r'^(\d+\.\d+)', 'BC', 'volts', 'V'), #ultiplier=1, divisor=1,
    ('L3-L1', r'^(\d+\.\d+)', 'AC', 'volts', 'V'), #ultiplier=1, divisor=1,

    ('Power', r'^(\d+\.\d+)', 'ABC', 'true_power', 'kW'), #ultiplier=1, divisor=1,
    ('Apparent Power', r'^(\d+\.\d+)', 'ABC', 'apparent_power', 'kVA'), #ultiplier=1, divisor=1,
    ('Reactive Power', r'^(\d+\.\d+)', 'ABC', 'reactive_power', 'kVAR'), #ultiplier=1, divisor=1,
    ('True Power Factor', r'^(\d+\.\d+)', 'ABC', 'pf', 'PF'), #ultiplier=1, divisor=1,

    # meters
    ('Energy', r'^(\d+\.\d+)', 'ABC', 'true_energy', 'kWh'), #ultiplier=1000, divisor=1,
    ('Apparent Energy', r'^(\d+\.\d+)', 'ABC', 'apparent_energy', 'kVAh'), #ultiplier=1000, divisor=1,
    ]
class PQube(SmapDriver):
    def setup(self, opts):
        self.serverloc = opts['Address']
        self.rate = opts.get('Rate', 10)
        for (field, regexp, phase, channel, fmt) in PQUBE_POINTS:
            self.add_timeseries('/%s/%s' % (phase, channel), fmt, data_type="double")
            self.set_metadata('/%s' % phase, {
                'Extra/Phase' : phase})

        self.set_metadata('/', {
            'Instrument/Manufacturer' : 'Power Standards Laboratory',
            'Instrument/SamplingPeriod' : str(self.rate),
            'Extra/Driver' : 'smap.drivers.pqube.PQube',
            })

    def start(self):
        print "satrtin"
        periodicSequentialCall(self.update).start(self.rate)
        
    def update(self):
        logging.debug("Updating " + self.serverloc)
        try:
            print "loading", self.serverloc + '/Meters.htm'
            fp = urllib2.urlopen(self.serverloc + '/Meters.htm', timeout=15)
            html = fp.read()
        except IOError, e:
            logging.error("IOError while reading pqube: url: %s exception: %s" % (url, str(e)))
            return
        except httplib.HTTPException, e:
            logging.error("HTTP exception reading pqube: url: %s exception: %s" % (url, str(e)))
            return

        reading_time = int(time.time())
        # this pulls out a list of all the channel-reading pairs
        data = re.findall('<td.*? class="channel">(.*?)</td>.*?<td.*?>(.*?)</td>',
                          html.lower())
        data = [(re.sub('<.*>', '', k), v) for (k,v) in data]
        data_map = {}
        data_map.update(data)

        for (field, regexp, phase, channel, fmt) in PQUBE_POINTS:
            reading = data_map.get(field.lower())
            if not reading: 
                logging.warn(field + " not found in doc")
                continue
            match = re.search(regexp, reading)
            if not match: 
                logging.warn("reading conversion failed: " + reading)
                continue

            self.add('/%s/%s' % (phase, channel), reading_time, float(match.groups(0)[0]))

