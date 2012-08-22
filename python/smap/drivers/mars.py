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

import time
import calendar
from xml.etree import ElementTree

from twisted.internet import defer
from twisted.web import client
from twisted.python import log

from smap import util
from smap.driver import SmapDriver

class CuriosityWeather(SmapDriver):
    """Periodically scrape data from Mars
    """
    
    FIELDS = {
        'min_temp': ("C"),
        'max_temp': ("C"),
        'pressure': ('hPa'),
        'abs_humidity': ("%"),
        'wind_speed': ('m/s'),
        # 'sol': ('days'),
        }

    @defer.inlineCallbacks
    def scrape(self):
        try:
            page = yield client.getPage("http://cab.inta-csic.es/rems/rems_weather.xml")
        except:
            log.msg()
            return

        root = ElementTree.fromstring(page)
        magnitudes = root.find("magnitudes")
        date = time.strptime(root.find("terrestrial_date").text, "%b %d, %Y")
        date = calendar.timegm(date)

        for stream in self.FIELDS.iterkeys():
            self._add('/' + stream, date, float(magnitudes.find(stream).text))

    def setup(self, opts):
        for stream, meta in self.FIELDS.iteritems():
            self.add_timeseries('/' + stream, meta[0],
                                data_type='double',
                                timezone='Utc')

    def start(self):
        self.scraper = util.PeriodicCaller(self.scrape, (), where="reactor")
        self.scraper.start(900)

    def stop(self):
        self.scraper.stop()
