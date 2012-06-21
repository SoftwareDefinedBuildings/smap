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
import datetime
import re
from smap.contrib import dtutil

from smap.drivers.scraper import ScraperDriver

urllib2.install_opener(urllib2.build_opener())

class IsoNEDriver(ScraperDriver):
    """Periodically scrape data from ISO-NE and publish it as sMAP feeds
    """
    DATA_TYPES = { "zone_lmp": {"Uri": 'http://www.iso-ne.com/histRpts/'
                                'rolling-dart/da_rt_lmp_<DATE_HERE>.csv',
                                "Description": "", "Unit": "$/MWh"},
                    "five_min_load": {"Uri": 'http://www.iso-ne.com/histRpts/'
                                    '5min-demand/demand_5min_<DATE_HERE>.csv', 
                                "Description": "", "Unit": "MW" }, 
                    "da_load": {"Uri": 'http://www.iso-ne.com/histRpts/'
                                        'da-hcd/da_demand_<DATE_HERE>.csv', 
                                "Description": "", "Unit": "MW" },
                    "finalzone_lmp": {"Uri": 'http://www.iso-ne.com/histRpts/'
                                    'rt-lmp/lmp_rt_final_<DATE_HERE>.csv', 
                                "Description": "", "Unit": "$/MWh"}
                   }

 

    def scrape(self):
        self.isone_out = {"Load": {}, "Generation": {}, "SPP": {}, "LMP": {} }
        self.five_min_load()
        self.zone_lmp()
        self.da_load()
        self.finalzone_lmp()
        return self.isone_out

    def five_min_load(self):
        try:
            dat = urllib2.urlopen(self.urlgen('http://www.iso-ne.com/histRpts/'
                                '5min-demand/demand_5min_', '.csv', 0))
        except:
            dat = urllib2.urlopen(self.urlgen('http://www.iso-ne.com/histRpts/'
                                '5min-demand/demand_5min_', '.csv', -1))
        lines = dat.readlines()
        dat.close()
        header, units, lines = self.isoneBaseParse(lines, 5)
        ts = []
        for line in lines:
            ts.append([self.parse_time(line[1].replace('"', '')), 
                                                        float(line[2])])
        self.isone_out["Load"]["Total Area"] = {"Actual": ts}

    def zone_lmp(self):
        try:
            dat = urllib2.urlopen(self.urlgen('http://www.iso-ne.com/histRpts/'
                                        'rolling-dart/da_rt_lmp_', '.csv', 0))
        except:
            dat = urllib2.urlopen(self.urlgen('http://www.iso-ne.com/histRpts/'
                                        'rolling-dart/da_rt_lmp_', '.csv', -1))

        lines = dat.readlines()
        dat.close()
        header, units, lines = self.isoneBaseParse(lines, 6)
        for line in lines:
            dt = line[1].replace('"', '')
            hr = line[2].replace('"', '')
            time = self.parse_time24(dt, hr, 0)
            datime = self.parse_time24(dt, hr, 1)
            place = (line[4] + " " + line[5]).replace('"', '')
            
            if place not in self.isone_out["LMP"].keys():
                self.isone_out["LMP"][place] = {"Forecasted": [], "Forecasted "
                "Energy Component": [], "Forecasted Congestion Component": [], 
                "Forecasted Marginal Loss Component": [], "Preliminary Actual": 
                [], "Preliminary Actual Energy Component": [], 
                "Preliminary Actual Congestion Component": [], 
                "Preliminary Actual Marginal Loss Component": [] }
            
            vals = []
            for x in range(6, 14):
                temp = line[x]
                if temp in '' or temp in '\n':
                    vals.append(0.0)
                else:
                    vals.append(float(temp))
            self.isone_out["LMP"][place]["Forecasted"].append([datime, vals[0]])
            self.isone_out["LMP"][place]["Forecasted Energy Component"].append(
                                                             [datime, vals[1]])
            self.isone_out["LMP"][place]["Forecasted Congestion "
                                          "Component"].append([datime, vals[2]])
            self.isone_out["LMP"][place]["Forecasted Marginal Loss "
                                         "Component"].append([datime, vals[3]])
            self.isone_out["LMP"][place]["Preliminary Actual"].append(
                                                                [time, vals[4]])
            self.isone_out["LMP"][place]["Preliminary Actual Energy "
                                          "Component"].append([time, vals[5]])
            self.isone_out["LMP"][place]["Preliminary Actual Congestion "
                                            "Component"].append([time, vals[6]])
            self.isone_out["LMP"][place]["Preliminary Actual Marginal Loss "
                                            "Component"].append([time, vals[7]])

    def da_load(self):
        try:
            dat = urllib2.urlopen(self.urlgen('http://www.iso-ne.com/histRpts/'
                                        'da-hcd/da_demand_', '.csv', 1))
        except:
            dat = urllib2.urlopen(self.urlgen('http://www.iso-ne.com/histRpts/'
                                        'da-hcd/da_demand_', '.csv', 0))
        lines = dat.readlines()
        dat.close()
        header, units, lines = self.isoneBaseParse(lines, 5)
        ts = []
        for line in lines:
            t = self.parse_time24(line[1].replace('"', ''), line[2].replace('"',
                                    ''), 0)
            ts.append([t, float(line[3])])
        self.isone_out["Load"]["Total Area"]["Day-Ahead Cleared"] = ts

    def finalzone_lmp(self):
        try:
            dat = urllib2.urlopen(self.urlgen('http://www.iso-ne.com/histRpts/'
                                           'rt-lmp/lmp_rt_final_', '.csv', -1))
        except:
            dat = urllib2.urlopen(self.urlgen('http://www.iso-ne.com/histRpts/'
                                           'rt-lmp/lmp_rt_final_', '.csv', -2))

        lines = dat.readlines()
        dat.close()
        header, units, lines = self.isoneBaseParse(lines, 6)
        for line in lines:
            dt = line[1].replace('"', '')
            hr = line[2].replace('"', '')
            time = self.parse_time24(dt, hr, 0)
            datime = self.parse_time24(dt, hr, 1)
            place = (line[4] + " " + line[5]).replace('"', '')
            
            if "Final Actual" not in self.isone_out["LMP"][place].keys():
                self.isone_out["LMP"][place]["Final Actual"] = []
                self.isone_out["LMP"][place]["Final Actual Energy "
                                                            "Component"] = []
                self.isone_out["LMP"][place]["Final Actual Congestion "
                                                            "Component"] = []
                self.isone_out["LMP"][place]["Final Actual "
                                                "Marginal Loss Component"] = []
            vals = []
            for x in range(6, 10):
                temp = line[x]
                if temp in '' or temp in '\n':
                    vals.append(0.0)
                else:
                    vals.append(float(temp))
            self.isone_out["LMP"][place]["Final Actual"].append(
                                                                [time, vals[0]])
            self.isone_out["LMP"][place]["Final Actual Energy "
                                        "Component"].append([time, vals[1]])
            self.isone_out["LMP"][place]["Final Actual Congestion "
                                            "Component"].append([time, vals[2]])
            self.isone_out["LMP"][place]["Final Actual Marginal Loss "
                                            "Component"].append([time, vals[3]])


    def parse_time(self, t):
        t = time.strptime(t, "%Y-%m-%d %H:%M:%S")
        return int(time.mktime(t))

    def parse_time24(self, dt, hr, daydelta):
        if "24" in hr:
            daydelta += 1
            dt = (datetime.datetime.strptime(dt, "%Y-%m-%d") + 
                                        datetime.timedelta(days=daydelta))
        else:
            dt = (datetime.datetime.strptime(dt + " " + hr, "%Y-%m-%d %H") +
                                        datetime.timedelta(days=daydelta))
        t = time.mktime(dt.timetuple())
        return int(t)

    def urlgen(self, pt1, pt2, deltadays):
        isotime = (dtutil.now("America/New_York") +
                                        datetime.timedelta(days=deltadays))
        isotime = isotime.strftime("%Y%m%d")
        return pt1 + isotime + pt2
        
    def isoneBaseParse(self, lines, initialskip):
        out = []
        for _x in range(initialskip-2):
            lines.pop(0)
        header = lines.pop(0)
        units = lines.pop(0)
        for line in lines:
            out.append(line.split(','))
        out.pop()
        return [header, units, out]

    def namer(self, namestr):
        if namestr in ["Actual"]:
            namestr = "five_min_load"
        elif namestr in ["Forecasted", "Forecasted Energy Component", 
                "Forecasted Congestion Component", 
                "Forecasted Marginal Loss Component", 
                "Preliminary Actual",
                "Preliminary Actual Energy Component",
                "Preliminary Actual Congestion Component",
                "Preliminary Actual Marginal Loss Component"]:
            namestr = "zone_lmp"
        elif namestr in ["Day-Ahead Cleared"]:
            namestr = "da_load"
        elif namestr in ["Final Actual", "Final Actual Energy Component",
                                        "Final Actual Congestion Component",
                                        "Final Actual Marginal Loss Component"]:
            namestr = "finalzone_lmp"
        return namestr

    def setup(self, opts):
        self.lastLatests = {}
        self.update_frequency = 300
        scraped = self.scrape()
        namer = self.namer
        for data_type in scraped.keys():
            for location in scraped[data_type].keys():
                for valtype in scraped[data_type][location].keys():
                    path = "/" + data_type + "/" + location + "/" + valtype
                    temp = self.add_timeseries(path, "ISO-NE" + data_type + 
                                location + valtype,
                                  self.DATA_TYPES[namer(valtype)]["Unit"],
                                        data_type = "double", description =
                              valtype + " " + data_type + " (" + location + ")")
                    temp['Metadata'] = { 'Location' : {'Country': 'USA', 'Area': 
                         'Northeast', 'Uri': 
                                        self.DATA_TYPES[namer(valtype)]["Uri"]}, 
                                        'Extra' : {'ISOName': 'ISO-NE', 
                                   'ISOType': data_type, 'ISOSubType': location,
                                            'ISODataType': valtype }
                                } 
                    temp['Properties']['Timezone'] = "America/New_York"
                    self.lastLatests[path] = None
                    
                 
if __name__ == '__main__':
    a = IsoNEDriver()
    b = a.scrape()
    print(b)
