"""
Copyright (c) 2014, Regents of the University of California
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
@author Anthony Sutardja <anthonysutardja@berkeley.edu>
@author Andrew Fang <andrewbfang@berkeley.edu>
"""
                                                                                
import urllib2

from BeautifulSoup import BeautifulSoup

from smap.driver import SmapDriver
from smap.util import periodicSequentialCall

from twisted.python import log


class AQMDriver(SmapDriver):
    SENSORS = {
        'Humidity': {
            'unit': '%RH',
            'type': 'double',
            'desc': 'Relative humidity',
        },
        'Temperature': {
            'unit': 'F',
            'type': 'double',
            'desc': 'Temperature in degrees F',
        },
        'Gas Concentration': {
            'unit': 'ppm',
            'type': 'double',
            'desc': 'Gas concentration expressed in ppm',
        },
    }

    def setup(self, opts):
        self.ip = opts.get('ip', None)
        self.tz = opts.get('Timezone', 'America/Los_Angeles')
        self.rate = float(opts.get('Rate', 1))  # seconds between update

        for sensor in self.SENSORS.keys():
            temp = self.add_timeseries(
                '/' + sensor,  # path
                self.SENSORS[sensor]['unit'],  # unit for reading
                data_type = self.SENSORS[sensor]['type'],  # reading type
                description = self.SENSORS[sensor]['desc'],
                timezone = self.tz
            )

    def start(self):
        periodicSequentialCall(self.read).start(self.rate)

    def read(self):
        readings = self.fetch_sensor_readings()

        if readings:
            # add to time series
            for sensor in self.SENSORS.keys():
                self.add('/' + sensor, readings[sensor])

    def fetch_sensor_readings(self):
        try:
            url = 'http://' + self.ip + '/status.xml'
            u = urllib2.urlopen(url)
        except urllib2.URLError:
            log.err()
            pass
        except urllib2.HTTPError:
            log.err()
            pass
        else:
            els = BeautifulSoup(u.read())
            d = {}

            try:
                d['Temperature'] = float(els.tm0.contents[0])
                d['Humidity'] = float(els.hu0.contents[0])
                d['Gas Concentration'] = float(els.gpn0.contents[0])
            except ValueError:
                log.err()
                pass
            else:
                return d
