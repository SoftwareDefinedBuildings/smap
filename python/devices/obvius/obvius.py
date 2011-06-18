#!/usr/bin/env python

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

import sensordb
import auth

urllib2.install_opener(urllib2.build_opener())

def to_pathname(s):
    s = re.sub('[\W/]+', '_', s)
    return s.lower()

class ObviusUpdater(threading.Thread):
    def __init__(self, meters, period=10):
        threading.Thread.__init__(self)
        self.meters = meters
        self.setDaemon(True)

    def open_url(self, url, AUTH):
        """Open a URL using urllib2, sending HTTP Basic authentication"""
        mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
        url_p = urlparse.urlparse(url)
        mgr.add_password(None, url_p.netloc, AUTH[0], AUTH[1])
        handler = urllib2.HTTPBasicAuthHandler(mgr)
        opener = urllib2.build_opener(handler)
        return opener.open(url, timeout=15)

    def is_sensor(self, channel, OBVIUS_SENSORS):
        for (x,y,z,p,q) in OBVIUS_SENSORS:
            if p == channel:
                return True
        return False

    def run(self):
        while True:
            start = time.time()
            for (meter, url, OBVIUS_SENSORS, OBVIUS_METERS, AUTH) in self.meters:
                logging.debug("Updating " + url)

                try:
                    fp = self.open_url(url, AUTH)
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
                        # print field, "->", match.groups(0)[0]
        
                        if self.is_sensor(channel, OBVIUS_SENSORS):
                            # print "sensor add", point
                            meter['data'][phase]['sensor'][channel].add(point)
                        else:
                            meter['data'][phase]['meter'][channel].add(point)

                    meter.push()
        
                except IOError, e:
                    logging.error("Failed to load meter: %s: %s" % (url, str(e)))
            while time.time() - start < conf.PERIOD:
                sleeptime = conf.PERIOD - (time.time() - start)
                if sleeptime > 0:
                    time.sleep(sleeptime)

def rinit(d, path):
    if len(path) == 0:
        return
    else:
        if not d.get(path[0]):
            d[path[0]] = {}

        rinit(d[path[0]], path[1:])

class ObviusDevice(dict):
    def __init__(self, OBVIUS_SENSORS, OBVIUS_METERS):
        param = SmapPoint.Parameter(interval=conf.PERIOD, time='second')
        for x,y,ph,name,fmt in OBVIUS_SENSORS:
            rinit(self, [ph, 'sensor', name])
            self.get(ph)['sensor'][name] = SmapPoint.SmapPoint(fmt, param)
        for x,y,ph,name,fmt in OBVIUS_METERS:
            rinit(self, [ph, 'meter', name])
            self.get(ph)['meter'][name] = SmapPoint.SmapPoint(fmt, param)
            

if __name__ == '__main__':
    import logging
    smaplog.start_log(screenLevel=logging.DEBUG)

    web_root = {}
    for building,m in conf.CONF.iteritems():
        for_updater = []
        for device, c in m.iteritems():
            (type, url) = c
            # make sure we have a mapping for this guy
            if not type in sensordb.TYPES: continue
            if not building in auth.AUTH: continue
            mappings = [x for x in sensordb.DB if x['obviusname'] == type][0]

            me = ObviusDevice(mappings['sensors'], mappings['meters'])
            inst = SmapInstance.SmapInstance(me, key='obvius-' + building + '-' + device)
            for_updater.append((inst, url, 
                                mappings['sensors'], mappings['meters'],
                                auth.AUTH[building]))

            l1 = web_root.get(to_pathname(building), {})
            l1[to_pathname(device)] = inst
            web_root[to_pathname(building)] = l1

        updater = ObviusUpdater(for_updater)
        updater.start()

    SmapHttp.start_server(web_root, port=conf.PORT)
