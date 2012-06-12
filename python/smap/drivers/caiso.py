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
modified to use ScraperDriver by:
@author Sagar Karandikar <skarandikar@berkeley.edu>
"""

import time
import urllib2

from smap.drivers.scraper import ScraperDriver

urllib2.install_opener(urllib2.build_opener())

class CaIsoDriver(ScraperDriver):
    """Periodically scrape data from CAISO and publish it as sMAP feeds
    """
    DATA_TYPES = { "Load": {"Unit": "MW", "Description": "Load"},
                   "Generation": {"Unit": "MW", "Description": 
                    "Generated Available Resources"}
                 }
    
    def scrape(self):
        caiso = urllib2.urlopen('http://content.caiso.com/outlook/'
                                                            'systemstatus.csv')
        lines = caiso.readlines()
        caiso.close()
        caiso_output = { 'Load': {}, "Generation": {} }
        intermed_out = []
        for line in lines:
            intermed_out.append(line.strip().split(","))
        intermed_out.pop(0)
        actualdemand = intermed_out.pop(0)
        utime = time.mktime(time.strptime(actualdemand[2], "%d-%b-%y %H:%M:%S"))
        utime = int(utime)
        caiso_output["Load"] = {"Total Area": {"Actual": [[utime,
                                                     float(actualdemand[1])]]}}
        actualgen = intermed_out.pop(0)
        caiso_output["Generation"] = {"Total Area": {"Actual": [[utime,
                                                      float(actualgen[1])]]}}
        return caiso_output
                
    def setup(self, opts):
        self.lastLatests = {}
        self.update_frequency = 300
        scraped = self.scrape()
        
        for data_type in scraped.keys():
            for location in scraped[data_type].keys():
                for valtype in scraped[data_type][location].keys():
                    path = "/" + data_type + "/" + location + "/" + valtype
                    temp = self.add_timeseries(path, "CAISO" + data_type + 
                                location + valtype,
                             self.DATA_TYPES[data_type]["Unit"], data_type 
                             = "double", description =
                                self.DATA_TYPES[data_type]["Description"])
                    temp['Metadata'] = { 'Location' : {'Country': 'USA', 'Area': 
                            'California', 'Uri': 'http://content.caiso.'
                                    'com/outlook/systemstatus.csv'
                                    }, 'Extra' : {'ISOName': 'CAISO', 
                                   'ISOType': data_type, 'ISOSubType': location,
                                            'ISODataType': valtype }
                                }
                    temp['Properties']['Timezone'] = "America/Los_Angeles"
                    self.lastLatests[path] = None
                    
                 

