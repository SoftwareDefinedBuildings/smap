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
@author Jay Taneja <taneja@cs.berkeley.edu>
"""

import time
import calendar
import re
import urllib2, base64
import logging,os,sys

from twisted.internet import defer
from twisted.web import client

from twisted.python import log

from smap import util
from smap.driver import SmapDriver

class NT160e(SmapDriver):
    """Periodically scrape data from Proliphix NT160e thermostat"""

    # 'Name of field': ("Units",[1st or 2nd group],[zero-indexed column])
    FIELDS = {
        'zone_temp': ('C','avgtemp ='),
        'humidity': ('rh','printFSC\("Relative Humidity"'),
        'cool_setting': ('C','printFSC\("Cool Setting"'),
        'heat_setting': ('F','printFSC\("Heat Setting"'),
        'schedule_cool': ('C','printFSC\("Cool"'),
        'schedule_heat': ('C','printFSC\("Heat"'),
        'hvac_state': ('state','hvacStateS =')
    }

    def convertTemperature(self, temp, scale):
        if scale.upper() == 'FAHRENHEIT':
            return (float(temp) - 32) / 1.8
        else:
            return float(temp)

#    @defer.inlineCallbacks
    def scrape(self):
        current_values = {}
        try:
            request = urllib2.Request(self.baseurl + 'index.shtml')
            base64string = base64.encodestring('%s:%s' % (self.auth[0], self.auth[1])).replace('\n', '')
            request.add_header("Authorization", "Basic %s" % base64string)
            response = urllib2.urlopen(request)
            page1 = response.read()

            request = urllib2.Request(self.baseurl + 'settings.shtml')
            request.add_header("Authorization", "Basic %s" % base64string)
            response = urllib2.urlopen(request)

            page2 = response.read()

            scale = ''

            for line in page2.split('\n'):
                if re.match('printFSC\("Temperature Scale"', line):
                    scale = line.split('"')[3]
                    break

            for field in self.FIELDS.keys():
                items = re.search(self.FIELDS[field][1] + '.+', page1)
                if items:
                    if field == 'hvac_state':
                        state = items.group(0).split('"')[1]
                        if state.upper() == 'OFF':
                            value = 0
                        elif state.upper() == 'COOL':
                            value = 1
                        elif state.upper() == 'COOL2':
                            value = 2
                        elif state.upper() == 'HEAT':
                            value = 3
                        elif state.upper() == 'HEAT2':
                            value = 4
                        elif state.upper() == 'AUX HT':
                            value = 5
                        elif state.upper() == 'DELAY':
                            value = 6
                        else:
                            value = 7
                    elif field == 'zone_temp':
                        value = self.convertTemperature(items.group(0).split('"')[1],scale)
                    elif self.FIELDS[field][0] == 'C':
                        value = self.convertTemperature(items.group(0).split('"')[3],scale)
                    else:
                        value = items.group(0).split('"')[3]

                    if re.match('\D{1}',str(value)[-1]):
                        value = int(str(value)[:-1])
                    current_values[field] = float(value)
                    have_data = True
            reading_time = time.mktime(time.localtime())
        except Exception, e:
            print e
            fname = os.path.split(sys.exc_info()[2].tb_frame.f_code.co_filename)[1]
            log.err()
            logging.error('Error (' + str(sys.exc_info()[0]) + ') : ' + str(e) + ' from ' + fname + ':' + str(sys.exc_info()[2].tb_lineno))
            have_data = False

        if have_data == True:
            try:
                for field in self.FIELDS.keys():
#                    print reading_time,field,current_values[field]
                    self.add('/' + field, reading_time, current_values[field])
                have_data = False
            except Exception,e:
                print e
                fname = os.path.split(sys.exc_info()[2].tb_frame.f_code.co_filename)[1]
                log.err()
                logging.error('Error (' + str(sys.exc_info()[0]) + ') : ' + str(e) + ' from ' + fname + ':' + str(sys.exc_info()[2].tb_lineno))

    def setup(self, opts):
        self.baseurl = opts.get('url')
        self.auth = [opts.get('login'),opts.get('password')]

        for stream, meta in self.FIELDS.iteritems():
            log.msg('adding stream /' + opts.get('key') + '/' + stream)
            logging.info('adding stream /' + opts.get('key') + '/' + stream)
            self.add_timeseries('/' + stream, meta[0],
                                data_type='double',
                                timezone='America/Los_Angeles')

            self.set_metadata('/' + stream, {
                'Metadata/Extra/Measurement' : stream,
                })

        self.set_metadata('/', {
                'Location/Uri' : self.baseurl,
                'Metadata/Location/Area' : 'California',
                'Metadata/Location/Country' : 'USA',
                })

    def start(self):
        self.scraper = util.periodicSequentialCall(self.scrape)
        self.scraper.start(60)

    def stop(self):
        self.scraper.stop()
