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
#
# @author Jay Taneja <taneja@cs.berkeley.edu>
#

# sample config:
# [/cory]
# type = smap.drivers.forecastTemp.ForecastTempDriver
# Latitude = 37.875331
# Longitude = -122.258309
# LocationName = cory

import time
import urllib2
import re

from smap.driver import SmapDriver
from smap.util import periodicCallInThread

urllib2.install_opener(urllib2.build_opener())

class ForecastTempDriver(SmapDriver):
    """Periodically scrape the weather forecast from the NWS site and republish
    it as a sMAP feed.
    """

    def update(self):
        try:
            site = "http://www.weather.gov/forecasts/xml/SOAP_server/ndfdXMLclient.php?whichClient=NDFDgen&lat="
            site += str(self.latitude)
            site += "&lon="
            site += str(self.longitude)
            site += "&product=time-series&temp=temp&Submit=Submit"

            xmlData = urllib2.urlopen(site)
        except urllib2.URLError:
            pass
        except urllib2.HTTPError:
            pass
        except IOError:
            pass
        else:
            xmlStr = str(xmlData.read())
           
            readTime=re.search('<creation-date refresh-frequency=".*">(.*)Z</creation-date>',xmlStr)
            readTime=readTime.group(1)
            
            timesPat=re.compile('<start-valid-time>(.*)</start-valid-time>')
            times=timesPat.finditer(xmlStr)
            TIMES=[]
            for t in times:
                TIMES.append(t.group(1))

            tzhour=re.search('([+-]{1}\d{2}):\d{2}', TIMES[0])
            thisTime=time.mktime(time.strptime(readTime,'%Y-%m-%dT%H:%M:%S'))+(int(tzhour.group(1)) * 60 * 60)

            if self.lastProduced == None or self.lastProduced != thisTime:
                print "Updated reading"
                self.lastProduced = thisTime
                tempsPat=re.compile('<value>(.*)</value>')
                temps=tempsPat.finditer(xmlStr)
                TEMPS=[]
                for t in temps:
                    TEMPS.append(t.group(1))

                for i in range(len(TEMPS)):
                    if i < 8:
                        temp = (5.0/9.0) * (float(TEMPS[i]) - 32.0)
                        if time.daylight == 0:
                            hour = int(time.strftime('%H', time.strptime(TIMES[i],"%Y-%m-%dT%H:%M:%S-07:00")))
                        else:
                            hour = int(time.strftime('%H', time.strptime(TIMES[i],"%Y-%m-%dT%H:%M:%S-08:00"))) + 1
                        hour = "%02d" % hour

                        self.add('/%s00temp' % hour,thisTime, temp)
            xmlData.close()
            
    def setup(self, opts):
        self.latitude = opts.get('Latitude')
        self.longitude = opts.get('Longitude')
        self.name = opts.get('LocationName')
        self.lastProduced = None

        try:
            site = "http://www.weather.gov/forecasts/xml/SOAP_server/ndfdXMLclient.php?whichClient=NDFDgen&lat="
            site += str(self.latitude)
            site += "&lon="
            site += str(self.longitude)
            site += "&product=time-series&temp=temp&Submit=Submit"
           
            xmlData = urllib2.urlopen(site)
        except urllib2.URLError:
            print "urle"
            pass
        except IOError:
            print "ioe"
            pass        
        
        xmlStr=str(xmlData.read())

        timesPat=re.compile('<start-valid-time>(.*)</start-valid-time>')
        times=timesPat.finditer(xmlStr)

        timeCounter = 0
        # self.add_collection('/')        
        for t in times:
            if timeCounter < 8:
                if time.daylight == 0:
                    hour = int(time.strftime('%H', time.strptime(t.group(1),"%Y-%m-%dT%H:%M:%S-07:00")))
                else:
                    hour = int(time.strftime('%H', time.strptime(t.group(1),"%Y-%m-%dT%H:%M:%S-08:00"))) + 1
                hour = "%02d" % hour

                self.add_timeseries('/%s00temp' % hour, 'C', description='NWS temperature forecast',data_type='double')

                self.set_metadata('/', {'Location/Latitude': self.latitude, 'Location/Longitude' : self.longitude, 'Location/Country' : 'USA', 'Location/Uri' : site})
                timeCounter = timeCounter + 1

    def start(self):
        periodicCallInThread(self.update).start(60 * 2.5)
