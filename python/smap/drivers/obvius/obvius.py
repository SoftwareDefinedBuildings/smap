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

import smap.driver
from smap.util import periodicSequentialCall

import sensordb

urllib2.install_opener(urllib2.build_opener())

def to_pathname(s):
    s = re.sub('[\W/]+', '_', s)
    s = re.sub('_*$', '', s)
    return s.lower()

class Driver(smap.driver.SmapDriver):
    def setup(self, opts):
        self.url = opts['Url']
        self.auth = (opts['Username'], opts['Password'])
        self.mappings = [x for x in sensordb.DB if x['obviusname'] == opts['ObviusType']][0]
        self.period = opts.get('Period', 30)

        self.set_metadata('/', {
                'Extra/Driver' : 'smap.drivers.obvius',
                'Instrument/Model' : opts['ObviusType']
                })
                          
        # create all the channels
        for (field, regexp, phase, channel,fmt) in self.mappings['sensors'] + self.mappings['meters']:
            self.add_timeseries('/' + phase + '/' + channel, 
                                fmt, data_type='double')
            self.set_metadata('/' + phase, {
                'Extra/Phase' : phase })


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

    def start(self):
        periodicSequentialCall(self.update).start(self.period)
    
    def update(self):
        logging.debug("Updating " + self.url)

        try:
            fp = self.open_url(self.url, self.auth)
            html = fp.read()
            fp.close()

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

            for (field, regexp, phase, channel,fmt) in \
                    self.mappings['sensors'] + self.mappings['meters']:
                reading = data_map.get(field.lower())
                if not reading: 
                    logging.warn(field + " not found in doc")
                    continue
                match = re.search(regexp, reading)
                if not match: 
                    logging.warn("reading conversion failed: " + reading + " : " + field)
                    continue
                self.add('/' + phase + '/' + channel, reading_time, float(match.groups(0)[0]))

        except IOError, e:
            logging.error("Failed to load meter: %s: %s" % (self.url, str(e)))

