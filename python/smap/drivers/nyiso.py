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
from string import capwords

from smap.drivers.scraper import ScraperDriver
from smap.contrib import dtutil

urllib2.install_opener(urllib2.build_opener())

class NYIsoDriver(ScraperDriver):
    """Periodically scrape data from NYISO and publish it as sMAP feeds
    """

    ITER = 0
    DATA_TYPES = { "Forecasted Load": {"Unit": "MW", "Description": "Load",
                                            'Uri': 'http://mis.nyiso.com/'
                                         'public/csv/isolf/<date>isolf.csv'},
                 "Integrated Actual Load": {"Unit": "MW", "Description": "Load",
                                            'Uri': 'http://mis.nyiso.com/'
                          'public/csv/palIntegrated/<date>palIntegrated.csv'},
                    "Actual Load": {"Unit": "MW", "Description": "Load", 'Uri':
                           'http://mis.nyiso.com/public/csv/pal/<date>pal.csv'},
                      "Actual LMP": {"Unit": "$/MWh", "Description": "LMP",
                                            'Uri': 'http://mis.nyiso.com/'
                                    'public/realtime/realtime_zone_lbmp.csv'},
                    "Forecasted LMP": {"Unit": "$/MWh", "Description": "LMP",
                               'Uri': 'http://mis.nyiso.com/'
                                'public/csv/damlbmp/<date>damlbmp_zone.csv'},
         "Actual Marginal Cost Losses": {"Unit": "$/MWh", "Description":
                                                    "Marginal Cost Losses",
                                            'Uri': 'http://mis.nyiso.com/'
                                    'public/realtime/realtime_zone_lbmp.csv'},
     "Forecasted Marginal Cost Losses": {"Unit": "$/MWh", "Description":
                                                    "Marginal Cost Losses",
                                            'Uri': 'http://mis.nyiso.com/'
                                'public/csv/damlbmp/<date>damlbmp_zone.csv'},
    "Actual Flow Transfer Interface": {"Unit": "MW", "Description": 
                                                    "Transfer Interface",
                                            'Uri': 'http://mis.nyiso.com/'
               'public/csv/ExternalLimitsFlows/currentExternalLimitsFlows.csv'},
      "Negative Limit Transfer Interface": {"Unit": "MW", "Description": 
                                                    "Transfer Interface",
                                             'Uri': 'http://mis.nyiso.com/'
               'public/csv/ExternalLimitsFlows/currentExternalLimitsFlows.csv'},
     "Positive Limit Transfer Interface": {"Unit": "MW", "Description":
                                                    "Transfer Interface",
                                            'Uri': 'http://mis.nyiso.com/'
               'public/csv/ExternalLimitsFlows/currentExternalLimitsFlows.csv'},
    "Actual Marginal Cost Congestion": {"Unit": "$/MWh", "Description":
                                                "Marginal Cost Congestion",
                                            'Uri': 'http://mis.nyiso.com/'
                                    'public/realtime/realtime_zone_lbmp.csv'},
"Forecasted Marginal Cost Congestion": {"Unit": "$/MWh", "Description":
                                                "Marginal Cost Congestion",
                                             'Uri': 'http://mis.nyiso.com/'
                                'public/csv/damlbmp/<date>damlbmp_zone.csv'}
                 }
    
    def scrape(self):
        self.nyiso_out = { "Load": {}, "Transfer Interface": {}, "LMP": {},
                    "Marginal Cost Losses": {}, "Marginal Cost Congestion": {} }
        self.actual_load()
        self.pred_load()
        self.int_actual_load()
        self.forecast_lmp()
        self.actual_lmp()
        self.transfer_interface()
        return self.nyiso_out

    def actual_load(self):
        actload = urllib2.urlopen(self.urlgen('http://mis.nyiso.com/public/'
                                                'csv/pal/', 'pal.csv', 0))
        lines = actload.readlines()
        actload.close()
        lines.pop(0)
        for line in lines:
            temp = line.strip().split(",")
            temp[0] = temp[0].replace('"', '')
            temp[2] = self.match(temp[2].replace('"', ''))
            if len(temp[len(temp)-1]) == 0:
                continue
            point = [self.parse_time(temp[0], 0), float(temp[4])]
            if temp[2] in self.nyiso_out["Load"].keys():
                self.nyiso_out["Load"][temp[2]]["Actual"].append(point)
            else:
                self.nyiso_out["Load"][temp[2]] = {}
                self.nyiso_out["Load"][temp[2]]["Actual"] = [point]

    def pred_load(self):
        try:
            predload = urllib2.urlopen(self.urlgen('http://mis.nyiso.com/'
                                      'public/csv/isolf/', 'isolf.csv', 86400))
        except:
            predload = urllib2.urlopen(self.urlgen('http://mis.nyiso.com/'
                                      'public/csv/isolf/', 'isolf.csv', 0))
        lines = predload.readlines()
        predload.close()
        col = eval("[" + lines.pop(0).replace('"Time Stamp",', "") + "]")
        for x in range(len(col)):
            col[x] = self.match(col[x])
        for place in col:
            if place == self.match("NYISO"):
                col[col.index(self.match("NYISO"))] = "Total Area"
                place = "Total Area"
            if place not in self.nyiso_out["Load"].keys():
                self.nyiso_out["Load"][place] = { "Forecasted": [] }
            else:
                self.nyiso_out["Load"][place]["Forecasted"] = []
        for line in lines:
            temp = line.strip().split(",")
            thistime = self.parse_time(temp.pop(0).replace('"', ''), 1)
            for placeval in temp:
                point = [thistime, float(placeval)]
                self.nyiso_out["Load"][col[self.ITER]]["Forecasted"].append(
                                                                        point)
                self.inf_iterate(col)

    def int_actual_load(self):
        actload = urllib2.urlopen(self.urlgen('http://mis.nyiso.com/public/csv/'
                                    'palIntegrated/','palIntegrated.csv', 0))
        lines = actload.readlines()
        actload.close()
        lines.pop(0)
        for line in lines:
            temp = line.strip().split(",")
            temp[0] = temp[0].replace('"', '')
            temp[2] = self.match(temp[2].replace('"', ''))
            if len(temp[len(temp)-1]) == 0:
                continue
            point = [self.parse_time(temp[0], 0), float(temp[4])]
            if temp[2] in self.nyiso_out["Load"].keys():
                k = self.nyiso_out["Load"][temp[2]].keys()
                if "Integrated Actual" in k:
                    self.nyiso_out["Load"][temp[2]]["Integrated Actual"].append(
                                                                        point)
                else:
                    self.nyiso_out["Load"][temp[2]]["Integrated Actual"] = []
            else:
                self.nyiso_out["Load"][temp[2]] = {}
                self.nyiso_out["Load"][temp[2]]["Integrated Actual"] = [point]

    def forecast_lmp(self):
        #try except to handle inconsistent next-day upload time
        try:
            actload = urllib2.urlopen(self.urlgen('http://mis.nyiso.com/public'
                                    '/csv/damlbmp/','damlbmp_zone.csv', 86400))
        except:
            actload = urllib2.urlopen(self.urlgen('http://mis.nyiso.com/public'
                                    '/csv/damlbmp/','damlbmp_zone.csv', 0))
        lines = actload.readlines()
        actload.close()
        temps = []
        lines.pop(0)
        for line in lines:
            temp = line.strip().split(",")
            temp[0] = temp[0].replace('"', '')
            temp[1] = self.match(temp[1].replace('"', ''))
            temps.append(temp)
        first_place = temps[0][1]
        first = True
        for line in temps:
            if line[1] not in first_place or first:
                self.nyiso_out["LMP"][line[1]] = {}
                self.nyiso_out["LMP"][line[1]]["Forecasted"] = []
                self.nyiso_out["Marginal Cost Losses"][line[1]] = {}
                self.nyiso_out["Marginal Cost Losses"][line[1]]["Fore"
                                                                "casted"] = []
                self.nyiso_out["Marginal Cost Congestion"][line[1]] = {}
                self.nyiso_out["Marginal Cost Congestion"][line[1]]["Forecast"
                                                                    "ed"] = []
                first = False
            else:
                break
        for temp in temps:
            if len(temp) != 6:
                continue
            point = [self.parse_time(temp[0], 1), float(temp[3])]
            self.nyiso_out["LMP"][temp[1]]["Forecasted"].append(point)
            point = [self.parse_time(temp[0], 1), float(temp[4])]
            self.nyiso_out["Marginal Cost Losses"][temp[1]]["Fore"
                                                        "casted"].append(point)
            point = [self.parse_time(temp[0], 1), float(temp[5])]
            self.nyiso_out["Marginal Cost Congestion"][temp[1]]["Forecast"
                                                            "ed"].append(point)


    def actual_lmp(self):            
        actload = urllib2.urlopen('http://mis.nyiso.com/public/'
                                            'realtime/realtime_zone_lbmp.csv')
        lines = actload.readlines()
        actload.close()
        temps = []
        lines.pop(0)
        for line in lines:
            temp = line.strip().split(",")
            temp[0] = temp[0].replace('"', '')
            temp[1] = self.match(temp[1].replace('"', ''))
            temps.append(temp)
        first_place = temps[0][1]
        first = True
        for line in temps:
            if line[1] not in first_place or first:
                self.nyiso_out["LMP"][line[1]]["Actual"] = []
                self.nyiso_out["Marginal Cost Losses"][line[1]]["Act"
                                                                "ual"] = []
                self.nyiso_out["Marginal Cost Congestion"][line[1]]["Act"
                                                                    "ual"] = []
                first = False
            else:
                break
        for temp in temps:
            if len(temp) != 6:
                continue
            point = [self.parse_time(temp[0], 0), float(temp[3])]
            self.nyiso_out["LMP"][temp[1]]["Actual"].append(point)
            point = [self.parse_time(temp[0], 0), float(temp[4])]
            self.nyiso_out["Marginal Cost Losses"][temp[1]]["Act"
                                                        "ual"].append(point)
            point = [self.parse_time(temp[0], 0), float(temp[5])]
            self.nyiso_out["Marginal Cost Congestion"][temp[1]]["Actu"
                                                            "al"].append(point)


    def transfer_interface(self):
        trans_load = urllib2.urlopen('http://mis.nyiso.com/public/csv/External'
                            'LimitsFlows/currentExternalLimitsFlows.csv')
        lines = trans_load.readlines()
        lines.pop(0)
        trans_load.close()
        for line in lines:
            temp = line.strip().split(",")
            temp[0] = self.parse_time(temp[0], 1)
            assemble = {"Actual Flow": [[temp[0], float(temp[3])]], 
                                "Positive Limit": [[temp[0], float(temp[4])]], 
                                 "Negative Limit": [[temp[0], float(temp[5])]]}
            self.nyiso_out["Transfer Interface"][temp[1]] = assemble
            

    def inf_iterate(self, col):
        """Quick infinite iterator for column-to-data matching"""
        if self.ITER == len(col)-1:
            self.ITER = 0
        else:
            self.ITER += 1

    def parse_time(self, time_str, fmt_int):
        fmt_strs = ["%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M"]
        time_str = time.strptime(time_str, fmt_strs[fmt_int])
        data_time = time.mktime(time_str)
        return int(data_time)

    def match(self, name_string):
        """Match place names since NYISO does not capitalize uniformly"""
        return capwords(str.lower(name_string))

    def urlgen(self, prefix, suffix, offset):
        """Generate the url for nyiso feeds. The produced output is
        "Prefix"+date+"Suffix". The offset is used when requesting future or
        past dates, e.g. for forcasted load"""
        basetime = dtutil.now("America/New_York")
        reqtime = basetime + datetime.timedelta(seconds=offset)
        url = reqtime.strftime("%Y%m%d")
        url = prefix + url + suffix
        return url



    def setup(self, opts):
        self.lastLatests = {}
        self.update_frequency = 300
        scraped = self.scrape()
        
        for data_type in scraped.keys():
            for location in scraped[data_type].keys():
                for valtype in scraped[data_type][location].keys():
                    path = "/" + data_type + "/" + location + "/" + valtype
                    temp = self.add_timeseries(path, "NYISO" + data_type + 
                                location + valtype,
                             self.DATA_TYPES[valtype + " " + data_type]["Unit"], 
                                        data_type = "double", description =
                                                    valtype + " " + 
                      self.DATA_TYPES[valtype + " " + data_type]["Description"] 
                                                        + " for " + location)
                    temp['Metadata'] = { 'Location' : {'Country': 'USA', 'Area': 
                         'New York', 'Uri': self.DATA_TYPES[valtype
                      + " " + data_type]["Uri"]}, 'Extra' : {'ISOName': 'NYISO', 
                                'ISOType': data_type, 'ISOSubType': location,
                                            'ISODataType': valtype }
                                }
                    temp['Properties']['Timezone'] = "America/New_York"
                    self.lastLatests[path] = None
                    
                 

