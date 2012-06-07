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
@author Sagar Karandikar <skarandikar@berkeley.edu>
"""

import time
import urllib2
import re

from zope.interface import implements

from smap.driver import SmapDriver
from smap.drivers.scraper import ScraperDriver
from smap.util import periodicCallInThread

urllib2.install_opener(urllib2.build_opener())

class PJMDriver(ScraperDriver):
    """Periodically scrape data from PJM and publish it as sMAP feeds
    """
    DATA_TYPES = { "LMP": {"Unit": "$", "Description": "Locational Marginal"
                            "Pricing"},
                   "Transfer Interface": {"Unit": "MW", "Description": 
                            "Transfer Interface MW Values"},
                   "Load": {"Unit": "MW", "Description": "Load"}
                 }
    
    def scrape(self):
        """this method scrapes data and returns it for use by the updater. It 
        should be of the format: [[time, value], [time2, value2], etc.] Times 
        should increase left to right and should be in seconds (web data seems 
        to be in ms). This should be implemented by the subclass. Update handles 
        ignoring duplicate data, so just return it all."""
        pjm = urllib2.urlopen('http://www.pjm.com/pub/'
                              'account/lmpgen/lmppost.html')
        lines = pjm.readlines()
        pjm.close()
        pjm_output = { 'LMP': {}, 'Transfer Interface': {}, 'Load': {} }
        intermed_out = []
        while "Data Last Updated" not in lines[0]:
            lines.pop(0)
        for line in lines:
            templine = re.sub(r'\<.*?\>', '', line)
            templine = templine.replace('\n', '')
            templine = templine.replace('\t', '')
            templine = templine.strip()
            if len(templine) == 0:
                pass
            else:
                intermed_out.append(templine)
        intermed_out.pop(0)
        update_time = self.parse_time(intermed_out.pop(0))
        print(update_time)

        #start parsing LMP data, dump into dict
        for x in range(5):
            intermed_out.pop(0)
        while "500 KV Bus" not in intermed_out[0]:
            lmp_name = intermed_out.pop(0)
            lmp_type = intermed_out.pop(0)
            lmp_name = lmp_name + " " + lmp_type
            five_min = intermed_out.pop(0)
            one_hour = intermed_out.pop(0)
            this_lmp = {"FiveMin": float(five_min),
                        "OneHour": float(one_hour)}
            pjm_output["LMP"][lmp_name] = this_lmp
        for x in range(4):
            intermed_out.pop(0)
        while "PJM Transfer Interface Information" not in intermed_out[0]:
            lmp_name = intermed_out.pop(0) + " 500 KV Bus"
            five_min = intermed_out.pop(0)
            one_hour = intermed_out.pop(0)
            this_lmp = {"FiveMin": float(five_min),
                        "OneHour": float(one_hour)}
            pjm_output["LMP"][lmp_name] = this_lmp
        for x in range(5):
            intermed_out.pop(0)
        while "Name does not indicate direction." not in intermed_out[0]:
            int_name = intermed_out.pop(0)
            actual = float(intermed_out.pop(0))
            warning = float(intermed_out.pop(0))
            transfer = float(intermed_out.pop(0))
            this_int = {"Actual flow": actual, "Warning Level": warning, 
                        "Transfer Limit": transfer}
            pjm_output["Transfer Interface"][int_name] = this_int
        for x in range(6):
            intermed_out.pop(0)
        while "Loads are calculated from" not in intermed_out[0]:
            load_area = intermed_out.pop(0)
            load_val = float(intermed_out.pop(0))
            pjm_output["Load"][load_area] = {'Actual': load_val}
        return (pjm_output, update_time)

    def parse_time(self, time_str):
        time_str = time_str.replace(" EDT", "")
        time_str = time.strptime(time_str, "%a %b %d %H:%M:%S %Y")
        data_time = time.mktime(time_str)
        return int(data_time)
                
    def setup(self, opts):
        self.lastLatest = None
        self.update_frequency = 300
        scraped = self.scrape()
        time = scraped[1]
        scraped = scraped[0]
        
        for data_type in scraped.keys():
            for location in scraped[data_type].keys():
                for valtype in scraped[data_type][location].keys():
                    temp = self.add_timeseries("/" + data_type + "/" + location 
                             + "/" + valtype, location + valtype,
                             self.DATA_TYPES[data_type]["Unit"], data_type 
                             = "double", description =
                                self.DATA_TYPES[data_type]["Description"])
                    temp['Metadata'] = { 'Location' : {'Country': 'USA', 'Area': 
                                'PJM ISO', 'Uri': 'http://www.pjm.com/pub/acco'
                                    'unt/lmpgen/lmppost.html'
                                    }, 'Extra' : { 'ISO': 'PJM'}
                                }
                 

if __name__ == '__main__':
    a = PJMDriver()
    print(a.scrape())
