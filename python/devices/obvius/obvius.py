#!/usr/bin/env python
"""sMAP feed for an obvius aquisuite box configured with HTTP basic,
holding a three-phase electric meter.

Edit conf.py to hold your basic auth credentials, and the address of
your aquisuite box.
"""

import sys
import logging
import time
import calendar
import threading
import urllib2
import urlparse
import re
import signal

sys.path.append("../../newlib")

import conf as conf
import smaplog
import SmapPoint
import SmapInstance
import SmapHttp

urllib2.install_opener(urllib2.build_opener())
# signal.signal(signal.SIGINT, signal.SIG_DFL)

PERIOD = 30
OBVIUS_SENSORS = [
    ('I a', r'^(\d+\.\d+)', 'A', 'current',
     SmapPoint.Formatting(unit='A', multiplier=1, divisor=1, type='electric', ctype='sensor')),
    ('I b', r'^(\d+\.\d+)', 'B', 'current',
     SmapPoint.Formatting(unit='A', multiplier=1, divisor=1, type='electric', ctype='sensor')),
    ('I c', r'^(\d+\.\d+)', 'C', 'current',
     SmapPoint.Formatting(unit='A', multiplier=1, divisor=1, type='electric', ctype='sensor')),
    ('I demand', r'^(\d+\.\d+)', 'ABC', 'current_demand',
     SmapPoint.Formatting(unit='A', multiplier=1, divisor=1, type='electric', ctype='sensor')),

    ('I a demand', r'^(\d+\.\d+)', 'A', 'current_demand',
     SmapPoint.Formatting(unit='A', multiplier=1, divisor=1, type='electric', ctype='sensor')),
    ('I b demand', r'^(\d+\.\d+)', 'B', 'current_demand',
     SmapPoint.Formatting(unit='A', multiplier=1, divisor=1, type='electric', ctype='sensor')),
    ('I c demand', r'^(\d+\.\d+)', 'C', 'current_demand',
     SmapPoint.Formatting(unit='A', multiplier=1, divisor=1, type='electric', ctype='sensor')),

    ('I1 THD', r'^(\d+\.\d+)', 'A', 'thd',
     SmapPoint.Formatting(unit='pct', multiplier=1, divisor=1, type='electric', ctype='sensor')),
    ('I2 THD', r'^(\d+\.\d+)', 'B', 'thd',
     SmapPoint.Formatting(unit='pct', multiplier=1, divisor=1, type='electric', ctype='sensor')),
    ('I3 THD', r'^(\d+\.\d+)', 'C', 'thd',
     SmapPoint.Formatting(unit='pct', multiplier=1, divisor=1, type='electric', ctype='sensor')),

    ('Frequency', r'^(\d+\.\d+)', 'ABC', 'line_frequency',
     SmapPoint.Formatting(unit='Hz', multiplier=1, divisor=1, type='electric', ctype='sensor')),

    ('Vll AB', r'^(\d+)', 'AB', 'volts',
     SmapPoint.Formatting(unit='V', multiplier=1, divisor=1, type='electric', ctype='sensor')),
    ('Vll BC', r'^(\d+)', 'BC', 'volts',
     SmapPoint.Formatting(unit='V', multiplier=1, divisor=1, type='electric', ctype='sensor')),
    ('Vll CA', r'^(\d+)', 'AC', 'volts',
     SmapPoint.Formatting(unit='V', multiplier=1, divisor=1, type='electric', ctype='sensor')),

    ('kW total', r'^(\d+)', 'ABC', 'real_power',
     SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1, type='electric', ctype='sensor')),
    ('kVA total', r'^(\d+)', 'ABC', 'apparent_power',
     SmapPoint.Formatting(unit='kVA', multiplier=1, divisor=1, type='electric', ctype='sensor')),
    ('kVAR total', r'^(\d+)', 'ABC', 'reactive_power',
     SmapPoint.Formatting(unit='kVAR', multiplier=1, divisor=1, type='electric', ctype='sensor')),

    ('kW demand', r'^(\d+)', 'ABC', 'real_power_demand',
     SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1, type='electric', ctype='sensor')),
    ('kVA demand', r'^(\d+)', 'ABC', 'apparent_power_demand',
     SmapPoint.Formatting(unit='kVA', multiplier=1, divisor=1, type='electric', ctype='sensor')),
    ('kVAR demand', r'^(\d+)', 'ABC', 'reactive_power_demand',
     SmapPoint.Formatting(unit='kVAR', multiplier=1, divisor=1, type='electric', ctype='sensor')),

    ('PF sign total', r'^(-?\d+\.\d+)', 'ABC', 'pf',
     SmapPoint.Formatting(unit='PF', multiplier=1, divisor=1, type='electric', ctype='sensor'))
    ]

OBVIUS_METERS = [
    ('kWh del', r'^(\d+)', 'ABC', 'true_energy',
     SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1, type='electric', ctype='meter')),
    ('kWh rec', r'^(\d+)', 'ABC', 'true_energy_received',
     SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1, type='electric', ctype='meter')),

    ('kVARh del', r'^(\d+)', 'ABC', 'reactive_energy',
     SmapPoint.Formatting(unit='kVAR', multiplier=1, divisor=1, type='electric', ctype='meter')),
    ('kVARh rec', r'^(\d+)', 'ABC', 'reactive_energy_received',
     SmapPoint.Formatting(unit='kVAR', multiplier=1, divisor=1, type='electric', ctype='meter')),

    ('kVAh del+rec', r'^(\d+)', 'ABC', 'apparent_energy_net',
     SmapPoint.Formatting(unit='kVA', multiplier=1, divisor=1, type='electric', ctype='meter')),

    ('kWh a del', r'^(\d+)', 'A', 'true_energy',
     SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1, type='electric', ctype='meter')),
    ('kWh a rec', r'^(\d+)', 'A', 'true_energy_received',
     SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1, type='electric', ctype='meter')),
    ('kWh b del', r'^(\d+)', 'B', 'true_energy',
     SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1, type='electric', ctype='meter')),
    ('kWh b rec', r'^(\d+)', 'B', 'true_energy_received',
     SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1, type='electric', ctype='meter')),
    ('kWh c del', r'^(\d+)', 'C', 'true_energy',
     SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1, type='electric', ctype='meter')),
    ('kWh c rec', r'^(\d+)', 'C', 'true_energy_received',
     SmapPoint.Formatting(unit='kW', multiplier=1, divisor=1, type='electric', ctype='meter')),
    ]

class PQubeUpdater(threading.Thread):
    def __init__(self, meters, period=10):
        threading.Thread.__init__(self)
        self.meters = meters
        self.setDaemon(True)

    def open_url(self, url):
        """Open a URL using urllib2, sending HTTP Basic authentication"""
        mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
        url_p = urlparse.urlparse(url)
        mgr.add_password(None, url_p.netloc, conf.AUTH[0], conf.AUTH[1])
        handler = urllib2.HTTPBasicAuthHandler(mgr)
        opener = urllib2.build_opener(handler)
        return opener.open(url, timeout=15)

    def is_sensor(self, channel):
        for (x,y,z,p,q) in OBVIUS_SENSORS:
            if p == channel:
                return True
        return False

    def run(self):
        while True:
            start = time.time()
            for (meter, url) in self.meters:
                logging.debug("Updating " + url)

                try:
                    fp = self.open_url(url)
                    html = fp.read()

                    # the obvius timestamp is in UTC
                    reading_time = re.findall('<time.*?>(.*?)</time>', html)[0]
                    # pydoc says this is the right way to convert this timestamp
                    reading_time = time.strptime(reading_time + " UTC",
                                                 "%Y-%m-%d %H:%M:%S %Z")
                    reading_time = calendar.timegm(reading_time)
                    logging.debug("reading timestamp is " + str(reading_time))
                    
                    # this pulls out a list of all the channel-reading pairs
                    data = re.findall('<point.*?name="(.*?)".*?value="(.*?)".*?/>', html.lower())
                    data_map = {}
                    data_map.update(data)
        
                    for (field, regexp, phase, channel,fmt) in OBVIUS_SENSORS + OBVIUS_METERS:
                        reading = data_map.get(field.lower())
                        if not reading: 
                            logging.warn(field + " not found in doc")
                            continue
                        match = re.search(regexp, reading)
                        if not match: 
                            logging.warn("reading conversion failed: " + reading + " : " + field)
                            continue
                        point = SmapPoint.Reading(time=reading_time, value=float(match.groups(0)[0]),
                                                  min=None, max=None)
                        print field, "->", match.groups(0)[0]
        
                        if self.is_sensor(channel):
                            print "sensor add", point
                            meter['data'][phase]['sensor'][channel].add(point)
                        else:
                            meter['data'][phase]['meter'][channel].add(point)

                    meter.push()
        
                except IOError, e:
                    logging.error("Failed to load meter: %s: %s" % (url, str(e)))
            while time.time() - start < PERIOD:
                sleeptime = PERIOD - (time.time() - start)
                if sleeptime > 0:
                    time.sleep(sleeptime)

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
        for x,y,ph,name,fmt in OBVIUS_SENSORS:
            rinit(self, [ph, 'sensor', name])
            self.get(ph)['sensor'][name] = SmapPoint.SmapPoint(fmt, param)
        for x,y,ph,name,fmt in OBVIUS_METERS:
            rinit(self, [ph, 'meter', name])
            self.get(ph)['meter'][name] = SmapPoint.SmapPoint(fmt, param)
            

if __name__ == '__main__':
    web_root = {}
    for_updater = []
    for m,l in conf.CONF.iteritems():
        (url) = l
        me = PQubeMeter()
        inst = SmapInstance.SmapInstance(me, key='obvius-' + m)
        web_root[m] = inst
        for_updater.append((inst, url))
        
    updater = PQubeUpdater(for_updater)
    updater.start()

    SmapHttp.start_server(web_root, port=conf.SMAP_PORT)
