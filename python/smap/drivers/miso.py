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

from smap.drivers.scraper import ScraperDriver

urllib2.install_opener(urllib2.build_opener())

class MIsoDriver(ScraperDriver):
    """Periodically scrape data from MISO and publish it as sMAP feeds
    """
    DATA_TYPES = { "Forecasted Load": {"Unit": "MW", "Description": "Load",
                                            'Uri': 'https://www.midwestiso.'
                                        'org/ria/ptpTotalLoad.aspx?format=csv'},
                   "Wind Generation": {"Unit": "MWh", "Description": 
                                        "Generated Available Resources", 'Uri':
                                                    'https://www.midwestiso.'
                                     'org/ria/windgenResponse.aspx?format=csv'},
                    "Actual Load": {"Unit": "MW", "Description": "Load", 'Uri':
                                                    'https://www.midwestiso.'
                                        'org/ria/ptpTotalLoad.aspx?format=csv'},
                    "Cleared Demand Load": {"Unit": "MW",
                                                "Description": "/Load", 'Uri':
                                                'https://www.midwestiso.'
                                        'org/ria/ptpTotalLoad.aspx?format=csv'},
                    "Actual ACE": {"Unit": "None", "Description": "Area Control"
                                      " Error", "Uri": "https://www.midwestiso."
                                "org/ria/aceResponse.aspx?format=csv"}
                 }
    
    def scrape(self):
        miso1 = urllib2.urlopen('https://www.midwestiso.'
                                'org/ria/ptpTotalLoad.aspx?format=csv')
        lines = miso1.readlines()
        miso1.close()
        miso_output = { "Load": {}, "Generation": {}, "ACE": {} }
        timeseries = []
        temp = []
        lines.pop(0)
        lines.pop(0)
        while "Medium" not in lines[0]:
            temp.append(lines.pop(0))
        #lines.pop()
        for line in temp:
            line = line.replace("\r\n", "")
            line = line.split(",")
            line[1] = float(line[1])
            timeseries.append(line)
        timeseries = self.twentyfourfixer(0, timeseries)
        miso_output["Load"] = {"Total Area": {"Cleared Demand": timeseries}}
        #done cleared demand
        #start forecasted load
        timeseries = []
        temp = []
        lines.pop(0)
        lines.pop(0)
        while "FiveMin" not in lines[0]:
            temp.append(lines.pop(0))
        for line in temp:
            line = line.replace("\r\n", "")
            line = line.split(",")
            line[1] = float(line[1])
            timeseries.append(line)
        timeseries = self.twentyfourfixer(0, timeseries)
        miso_output["Load"]["Total Area"]["Forecasted"] = timeseries
        #done forecasted load
        #start actual load
        timeseries = []
        temp = []
        lines.pop(0)
        lines.pop(0)
        for line in lines:
            line = line.replace("\r\n", "")
            line = line.split(",")
            line[1] = float(line[1]) #convert MW values to floats
            timeseries.append(line)
        timeseries = self.twentyfourfixer(1, timeseries)
        miso_output["Load"]["Total Area"]["Actual"] = timeseries
        #done actual load
        #start wind generation
        miso2 = urllib2.urlopen('https://www.midwestiso.org/ria/'
                                            'windgenResponse.aspx?format=csv')
        lines = miso2.readlines()
        miso2.close()
        timeseries = []
        lines.pop(0) #removes the first line, which contains column headings
        for line in lines:
            temp = line.strip().replace('"', '').split(',')
            timeseries.append([int(temp[0])/1000, float(temp[3])])
        miso_output["Generation"] = {"Total Area": {"Wind": timeseries}}
        #done wind generation
        #start ACE
        miso3 = urllib2.urlopen('https://www.midwestiso.org/ria/aceResponse.'
                                                            'aspx?format=csv')
        lines = miso3.readlines()
        miso3.close()
        timeseries = []
        lines.pop(0) #removes the first line, which contains column headings
        for line in lines:
            temp = line.strip().replace('"', '').split(',')
            timeseries.append([int(temp[1])/1000, float(temp[2])])
        miso_output["ACE"] = {"Total Area": {"Actual": timeseries}}
        #done ACE
        return miso_output

    def twentyfourfixer(self, dtype, timeseries):
        dtypes = ["%d %b %Y %H", "%d %b %Y %H:%M"]
        current_date_str = time.strftime("%d %b %Y")
        for pair in timeseries:
            if pair[0] in "24":
                pair_time = current_date_str + " 0"
                pair_time = time.strptime(pair_time, dtypes[dtype])
                pair_time = int(time.mktime(pair_time))
                pair_time += 3600*24
                pair[0] = pair_time
            else:
                pair_time = current_date_str + " " + pair[0]
                pair_time = time.strptime(pair_time, dtypes[dtype])
                pair_time = int(time.mktime(pair_time))
                pair[0] = pair_time
        return timeseries

    def setup(self, opts):
        self.lastLatests = {}
        self.update_frequency = 300
        scraped = self.scrape()
        
        for data_type in scraped.keys():
            for location in scraped[data_type].keys():
                for valtype in scraped[data_type][location].keys():
                    path = "/" + data_type + "/" + location + "/" + valtype
                    temp = self.add_timeseries(path, "MISO" + data_type + 
                                location + valtype,
                             self.DATA_TYPES[valtype + " " + data_type]["Unit"], 
                                        data_type = "double", description =
                                                    valtype + " " + 
                      self.DATA_TYPES[valtype + " " + data_type]["Description"] 
                                                        + " for " + location)
                    temp['Metadata'] = { 'Location' : {'Country': 'USA', 'Area': 
                         'Midwest ISO Footprint', 'Uri': self.DATA_TYPES[valtype
                       + " " + data_type]["Uri"]}, 'Extra' : {'ISOName': 'MISO', 
                                   'ISOType': data_type, 'ISOSubType': location,
                                            'ISODataType': valtype }
                                }
                    temp['Properties']['Timezone'] = "America/New_York"
                    self.lastLatests[path] = None
                    
                 

