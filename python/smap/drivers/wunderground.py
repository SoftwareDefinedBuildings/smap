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
"""Driver to poll data from a Weather Underground weather station,
using their xml api.

Optional Parameters: 

"Address" : URI to fetch data from.  The driver will GET the URL,
and add a query parameter with the station id.

"ID" [default KCABERKE25] : wunderground station id

"Rate" [default 60] : number of seconds between polls.
"""

import urllib2
import rfc822
import datetime
import time
from xml.dom.minidom import parse, parseString
from xml.parsers.expat import ExpatError

from twisted.internet import reactor
from twisted.python import log
from smap import driver, util
from smap.contrib import dtutil

def get_val(dom, key):
    try:
        v = dom.getElementsByTagName(key)[0].firstChild.nodeValue
    except AttributeError:
        v = None
    return v

def parse_local(t):
    return datetime.datetime.strptime(t, "Last Updated on %B %d, %I:%M %p")

def guess_timezone(local, gmt):
    # parse the two timestamps
    zonename = local.split(' ')[-1]
    local = parse_local(local[:-4])
    gmt = datetime.datetime(*rfc822.parsedate_tz(gmt)[:5])
    # and fix the year since their string doesn't come with one
    local = local.replace(year=gmt.year)
    onames = dtutil.olson(zonename, local - gmt)
    if len(onames):
        log.msg("WARNING: inferred zone code %s for %s" % (onames[-1], zonename))
        return onames[-1]
    else:
        log.msg("WARNING: no match found for zone name %s with utcoffset %s" % 
                (zonename, str(local - gmt)))
        return zonename
    

class WunderGround(driver.SmapDriver):
    def setup(self, opts):
        self.url = opts.get("Address", 
                            "http://api.wunderground.com/weatherstation/WXCurrentObXML.asp")
        self.id = opts.get("ID", "KCABERKE25")
        self.rate = int(opts.get("Rate", 60))
        self.last_time = 0
        self.metadata_done = False
        self.tz = opts.get('Timezone', None)
       
        self.timeseries = [
                           {"path": "/wind_dir", "unit": "deg", "xml_nodename": "wind_degrees", "data_type": "long"},
                           {"path": "/wind_speed", "unit": "m/s", "xml_nodename": "wind_mph", "data_type": "double"},
                           {"path": "/wind_gust", "unit": "m/s", "xml_nodename": "wind_gust_mph", "data_type": "double"},
                           {"path": "/humidity", "unit": "rh", "xml_nodename": "relative_humidity", "data_type": "long"},
                           {"path": "/temperature", "unit": "C", "xml_nodename": "temp_c", "data_type": "double"},
                           {"path": "/pressure", "unit": "mb", "xml_nodename": "pressure_mb", "data_type": "double"},
                           {"path": "/dew_point", "unit": "C", "xml_nodename": "dewpoint_c", "data_type": "double"}
                          ]
        self.metadata = [
                         {"tag": "Extra/StationType", "xml_nodename": "station_type"},  
                         {"tag": "Location/StationID", "xml_nodename": "station_id"},  
                         {"tag": "Location/Latitude", "xml_nodename": "latitude"},  
                         {"tag": "Location/Longitude", "xml_nodename": "longitude"},  
                         {"tag": "Location/Altitude", "xml_nodename": "elevation"},  
                         {"tag": "Location/Uri", "xml_nodename": "link"},  
                         {"tag": "Location/City", "xml_nodename": "city"},  
                         {"tag": "Location/State", "xml_nodename": "state"}
                        ]

    def create_timeseries(self, dom):
        if not self.tz:
            try:
                local_time = get_val(dom, "observation_time")
                reading_time = get_val(dom, "observation_time_rfc822")
                tz = guess_timezone(local_time, reading_time)
            except Exception, e:
                tz = self.tz
                log.err()

        for ts in self.timeseries:
            self.add_timeseries(ts["path"], ts["unit"], data_type=ts["data_type"],
                                timezone=tz)
 
    def start(self):
        util.periodicSequentialCall(self.update).start(self.rate)

    def update(self):
        try:
            url = self.url + "?ID=" + self.id
            fh = urllib2.urlopen(url, timeout=10)
        except urllib2.URLError, e:
            log.err("URLError getting reading: [%s]: %s" % (url, str(e)))
            return
        except urllib2.HTTPError, e:
            log.err("HTTP Error: [%s]: %s" % (url, str(e)))
            return

        try:
            dom = parse(fh)
        except ExpatError, e:
            log.err("Exception parsing DOM [%s]: %s" % (url, str(e)))
            return

        if not self.metadata_done:
            self.create_timeseries(dom)

        try:
            reading_time = rfc822.parsedate_tz(get_val(dom, "observation_time_rfc822"))
            reading_time = int(rfc822.mktime_tz(reading_time))
        except Exception, e:
            log.err("Exception finding time [%s]: %s" % (url, str(e)))
            return

        if reading_time > self.last_time:
        
            for ts in self.timeseries:
                v = get_val(dom, ts["xml_nodename"])
                if v is not None:
                    if ts["data_type"] == "double":
                       v = float(v)
                    else:
                       v = int(v)
                    self.add(ts["path"], reading_time, v)
            
            last_time = reading_time
 
        if not self.metadata_done:
            self.metadata_done = True
            d = {}
            for m in self.metadata:
                v = get_val(dom, m["xml_nodename"])
                if v is not None:
                    d.update({m["tag"]: v})
                else:
                    d.update({m["tag"]: ""})

            self.set_metadata('/', d)

        dom.unlink()
