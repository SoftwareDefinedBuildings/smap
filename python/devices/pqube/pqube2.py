#!/usr/bin/env python

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

sys.path.append("../../newlib")

import conf as conf
import smaplog
import SmapPoint
import SmapInstance
import SmapHttp
import util

urllib2.install_opener(urllib2.build_opener())

PERIOD = 10
PQUBE_SENSORS = [
    ('L1-N', r'^(\d+\.\d+)', 'A', 'phase-neutral_voltage',
     SmapPoint.Formatting(unit='V', multiplier=1, divisor=1,
                          type='electric', ctype='sensor')),
    ('L2-N', r'^(\d+\.\d+)', 'B', 'phase-neutral_voltage',
     SmapPoint.Formatting(unit='V', multiplier=1, divisor=1,
                          type='electric', ctype='sensor')),
    ('L3-N', r'^(\d+\.\d+)', 'C', 'phase-neutral_voltage',
     SmapPoint.Formatting(unit='V', multiplier=1, divisor=1,
                          type='electric', ctype='sensor')),

    ('L1 Amp', r'^(\d+\.\d+)', 'A', 'current',
     SmapPoint.Formatting(unit='A', multiplier=1, divisor=1,
                          type='electric', ctype='sensor')),
    ('L2 Amp', r'^(\d+\.\d+)', 'B', 'current',
     SmapPoint.Formatting(unit='A', multiplier=1, divisor=1,
                          type='electric', ctype='sensor')),
    ('L3 Amp', r'^(\d+\.\d+)', 'C', 'current',
     SmapPoint.Formatting(unit='A', multiplier=1, divisor=1,
                          type='electric', ctype='sensor')),

#     ('L1-N Voltage Fundamental', r'^(\d+\.\d+)', 'A', 'a-n fundamental voltage'),
#     ('L1-N Voltage Fundamental', r'^(\d+\.\d+)', 'A', 'a-n fundamental phase'),
#     ('L2-N Voltage Fundamental', r'^(\d+\.\d+)', 'B', 'a-n fundamental voltage'),
#     ('L2-N Voltage Fundamental', r'^(\d+\.\d+)', 'B', 'a-n fundamental phase'),
#     ('L3-N Voltage Fundamental', r'^(\d+\.\d+)', 'C', 'a-n fundamental voltage'),
#     ('L3-N Voltage Fundamental', r'^(\d+\.\d+)', 'C', 'a-n fundamental phase'),

    ('Frequency', r'^(\d+\.\d+)', 'ABC', 'line_frequency',
     SmapPoint.Formatting(unit='Hz', multiplier=1, divisor=1,
                          type='electric', ctype='sensor')),
    ('Voltage THD', r'^(\d+\.\d+)', 'ABC', 'voltage_thd',
     SmapPoint.Formatting(unit='pct', multiplier=1, divisor=1,
                          type='electric', ctype='sensor')),
    ('Current TDD', r'^(\d+\.\d+)', 'ABC', 'current_tdd',
     SmapPoint.Formatting(unit='pct', multiplier=1, divisor=1,
                          type='electric', ctype='sensor')),

    ('L1-L2', r'^(\d+\.\d+)', 'AB', 'volts',
     SmapPoint.Formatting(unit='V', multiplier=1, divisor=1,
                          type='electric', ctype='sensor')),
    ('L2-L3', r'^(\d+\.\d+)', 'BC', 'volts',
     SmapPoint.Formatting(unit='V', multiplier=1, divisor=1,
                          type='electric', ctype='sensor')),
    ('L3-L1', r'^(\d+\.\d+)', 'AC', 'volts',
     SmapPoint.Formatting(unit='V', multiplier=1, divisor=1,
                          type='electric', ctype='sensor')),

    ('Power', r'^(\d+\.\d+)', 'ABC', 'true_power',
     SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1,
                          type='electric', ctype='sensor')),
    ('Apparent Power', r'^(\d+\.\d+)', 'ABC', 'apparent_power',
     SmapPoint.Formatting(unit='kVA', multiplier=1, divisor=1,
                          type='electric', ctype='sensor')),
    ('Reactive Power', r'^(\d+\.\d+)', 'ABC', 'reactive_power',
     SmapPoint.Formatting(unit='kVAR', multiplier=1, divisor=1,
                          type='electric', ctype='sensor')),
    ('True Power Factor', r'^(\d+\.\d+)', 'ABC', 'pf',
     SmapPoint.Formatting(unit='PF', multiplier=1, divisor=1,
                          type='electric', ctype='sensor'))
    ]

PQUBE_METERS = [
    ('Energy', r'^(\d+\.\d+)', 'ABC', 'true_energy',
     SmapPoint.Formatting(unit='kW', multiplier=1000, divisor=1,
                          type='electric', ctype='meter')),
    ('Apparent Energy', r'^(\d+\.\d+)', 'ABC', 'apparent_energy',
     SmapPoint.Formatting(unit='kW', multiplier=1000, divisor=1,
                          type='electric', ctype='meter'))
    ]


def is_sensor(channel):
    for (x,y,z,p,q) in PQUBE_SENSORS:
        if p == channel:
            return True
    return False

def update(meters):
    for (meter, url) in meters:
        logging.debug("Updating " + url)
        try:
            fp = urllib2.urlopen(url + '/Meters.htm', timeout=15)
            html = fp.read()
        except IOError, e:
            logging.error("IOError while reading pqube: url: %s exception: %s" % (url, str(e)))
            continue
        except httplib.HTTPException, e:
            logging.error("HTTP exception reading pqube: url: %s exception: %s" % (url, str(e)))
            continue

        reading_time = int(time.time())
        # this pulls out a list of all the channel-reading pairs
        data = re.findall('<td.*? class="channel">(.*?)</td>.*?<td.*?>(.*?)</td>',
                          html.lower())
        data = [(re.sub('<.*>', '', k), v) for (k,v) in data]
        data_map = {}
        data_map.update(data)

        for (field, regexp, phase, channel, fmt) in PQUBE_SENSORS + PQUBE_METERS:
            reading = data_map.get(field.lower())
            if not reading: 
                logging.warn(field + " not found in doc")
                continue
            match = re.search(regexp, reading)
            if not match: 
                logging.warn("reading conversion failed: " + reading)
                continue
            point = SmapPoint.Reading(time=reading_time, value=match.groups(0)[0],
                                      min=None, max=None)

            if is_sensor(channel):
                print "sensor add", point
                meter['data'][phase]['sensor'][channel].add(point)
            else:
                meter['data'][phase]['meter'][channel].add(point)
                        
        meter.push()
        
def rinit(d, path):
    if len(path) == 0:
        return
    else:
        if not d.get(path[0]):
            d[path[0]] = {}

        rinit(d[path[0]], path[1:])

class PQubeMeter(dict):
    def __init__(self):
        param = SmapPoint.Parameter(interval=PERIOD, time='second')
        for x,y,ph,name,fmt in PQUBE_SENSORS:
            rinit(self, [ph, 'sensor', name])
            self.get(ph)['sensor'][name] = SmapPoint.SmapPoint(fmt, param)
        for x,y,ph,name,fmt in PQUBE_METERS:
            rinit(self, [ph, 'meter', name])
            self.get(ph)['meter'][name] = SmapPoint.SmapPoint(fmt, param)
            

if __name__ == '__main__':
    web_root = {}
    for_updater = []
    for m,l in conf.CONF.iteritems():
        (url) = l
        me = PQubeMeter()
        inst = SmapInstance.SmapInstance(me, key='pqube-' + m)
        web_root[m] = inst
        for_updater.append((inst, url))

    SmapHttp.smap_server_init()
    u = util.RateTimer(PERIOD, lambda: update(for_updater))
    u.start()


    SmapHttp.start_server(web_root, port=8015)
