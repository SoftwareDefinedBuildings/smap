"""sMAP feed for grabbing the IMS feed from a Sun Blackbox
containerized datacenter.

conf.py controls which IMS feed to grab
"""
import sys
import logging
import time
import threading
import urllib2
import rfc822
import re
from xml.dom.minidom import parse, parseString
import signal
signal.signal(signal.SIGINT, signal.SIG_DFL)
sys.path.append("../../newlib")

from SmapPoint import SmapPoint, Formatting, Parameter, Reading
import SmapHttp
import SmapInstance
import smaplog

import conf as conf

def get_val(dom, key):
    v = dom.getElementsByTagName(key)
    return v

def make_onerack():
    racksensors = {}

    for i in range(1,6):
        racksensors['temp_%i' % i] = SmapPoint(Formatting(unit='C', multiplier=None, divisor=10, 
                                                          type='air', ctype='sensor'),
                                               Parameter(interval=20, time='second'))
        racksensors['fan_%i' % i] =  SmapPoint(Formatting(unit='pct', multiplier=None, divisor=None, 
                                                          type='fan speed', ctype='sensor'),
                                               Parameter(interval=20, time='second'))
    return {'sensor' : racksensors}

def make_env():
    env = {}
    env['temperature'] = SmapPoint(Formatting(unit='C', multiplier=None, divisor=10, 
                                              type='air', ctype='sensor'),
                                   Parameter(interval=20, time='second'))
    env['humidity'] = SmapPoint(Formatting(unit='rh', multiplier=None, divisor=10, 
                                           type='air', ctype='sensor'),
                                   Parameter(interval=20, time='second'))
    return {'sensor' : env}

def make_blackbox():
    racks = {}
    for i in range(1,9):
        racks['rack_%i' % i] = make_onerack()
    racks['internal'] = make_env()
    racks['external'] = make_env()
    return racks

class Updater(threading.Thread):
    def __init__(self, blackboxes):
        threading.Thread.__init__(self)
        self.blackboxes = blackboxes
        
    def run(self):
        last_times = {}
        while True:
            for (bbname, instance) in self.blackboxes.iteritems():
                logging.info("Updating meter reading")

                try: 
                    xml_loc = conf.CONF[bbname]
                    fh = urllib2.urlopen(xml_loc, timeout=10)
                except Exception, e:
                    logging.error("Opening resource failed: " + str(e))
                    continue
                dom = parse(fh)
            
                stime = dom.getElementsByTagName('date')[0].getElementsByTagName('string')[0].firstChild.nodeValue
                reading_time = rfc822.parsedate_tz(stime)
                reading_time = int(rfc822.mktime_tz(reading_time))

                # peel out the racks and let them update themselves
                if last_times.get(bbname, 0) < reading_time:
                    logging.info("New data!")
                    self._update(dom, reading_time, instance['data'])
                    instance.push()
                    last_times[bbname] = reading_time

#                 self.context['device']['Type'] = 'Sun Blackbox'
#                 self.context['device']['Serial'] = 
#                 dom.getElementsByTagName('name')[0].getElementsByTagName('string')[0].firstChild.nodeValue
#                 self.reporting.push()
                dom.unlink()
            time.sleep(30)
            

    def _update(self, dom, reading_time, instance):
        for subdom in dom.getElementsByTagName('measurement'):
            tag = subdom.getElementsByTagName('tag')[0].firstChild.nodeValue
            match = re.match('Rack(\d)Temp(\d)', tag)
            if match:
                (rack, sensor) = match.groups(1)
                val = subdom.getElementsByTagName('value')[0].firstChild.nodeValue
                instance['rack_%i' % int(rack)]['sensor']['temp_%i' % int(sensor)].add(Reading(time=reading_time,
                                                                                     value=int(float(val) * 10),
                                                                                     min=None, max=None))

            match = re.match('Rack(\d)Fan(\d)', tag)
            if match:
                (rack, sensor) = match.groups(1)
                val = subdom.getElementsByTagName('value')[0].firstChild.nodeValue
                instance['rack_%i' % int(rack)]['sensor']['fan_%i' % int(sensor)].add(Reading(time=reading_time,
                                                                                    value=int(float(val)),
                                                                                    min=None, max=None))

            (point, channel) = (None, None)
            if tag == 'InternalHumidityTemp': (point, channel) = ('internal', 'temperature')
            elif tag == 'InternalHumidity': (point, channel) = ('internal', 'humidity')
            elif tag == 'ExternalHumidityTemp': (point, channel) = ('external', 'temperature')
            elif tag == 'ExternalHumidity': (point, channel) = ('external', 'humidity')
            if point and channel:
                val = subdom.getElementsByTagName('value')[0].firstChild.nodeValue
                instance[point]['sensor'][channel].add(Reading(time=reading_time,
                                                               value=int(float(val) * 10),
                                                               min=None, max=None))

if __name__ == '__main__':
    smaplog.start_log()

    # load in all the ims feeds from the conf
    blackboxes = {}
    for m,l in conf.CONF.iteritems():
        (url) = l
        blackboxes[m] = SmapInstance.SmapInstance(make_blackbox(), key="blackbox-mdc1")
        blackboxes[m].start()

    u = Updater(blackboxes)
    u.start()

    # fire off the smap server
    SmapHttp.start_server(blackboxes, port=conf.SMAP_PORT)
