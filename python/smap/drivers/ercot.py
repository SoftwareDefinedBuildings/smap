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

class ErcotDriver(ScraperDriver):
    """Periodically scrape data from ERCOT and publish it as sMAP feeds
    """
    DATA_TYPES = { "Total Area Load": {"Uri": 'http://www.ercot.com/content/'
                                'cdr/html/loadForecastVsActualCurrentDay.html',
                                "Description": "Load", "Unit": "MW"},
                   "Total Generation": {"Uri": 'http://www.ercot.com/content/'
                                        'cdr/html/scedUpDown_currentDay.html',
                                "Description": "Generation", "Unit": "MW"},
                   "Wind Generation": {"Uri": 'http://www.ercot.com/content/'
                                            'cdr/html/CURRENT_DAYCOP_HSL.html',
                                 "Description": "Generation", "Unit": "MW"},
                    "Actual SPP": {"Uri": 'http://www.ercot.com/content/cdr/'
                                                        'html/real_time_spp', 
                        "Description": "Settlement Point Price", "Unit": "$"},
                    "Actual LMP": {"Uri": 'http://www.ercot.com/content/'
                                                'cdr/html/current_np6788',
                                        "Description": "Locational Marginal "
                                                    "Pricing", "Unit": "$"},
                    "Forecasted SPP": {"Uri": 'http://www.ercot.com/content/'
                                               'cdr/html/<DATE HERE>_dam_spp',
                       "Description": "Settlement Point Price", "Unit": "$"}
                  }

    def scrape(self):
        self.ercot_out = { "Load": {}, "Generation": {}, "SPP": {}, "LMP": {} }
        self.load_get()
        self.total_gen_get()
        self.wind_gen_get()
        self.SPP_get()
        self.real_LMP_get()
        self.forecast_SPP_get()
        return self.ercot_out

    def load_get(self):
        act = urllib2.urlopen(self.DATA_TYPES["Total Area Load"]["Uri"])
        lines = act.readlines()
        act.close()
        self.ercot_out["Load"]["Total Area"] = {}
        lines = self.ercot_strip(lines, lambda x: x)
        timeseries, lines = self.ercot_html_parse(lines, 0, 1, "System")
        self.ercot_out["Load"]["Total Area"]["Forecasted Today"] = timeseries
        timeseries, lines = self.ercot_html_parse(lines, 0, 1, "Day-Ahead")
        self.ercot_out["Load"]["Total Area"]["Actual"] = timeseries
        timeseries, lines = self.ercot_html_parse(lines, 1, 2, "Day-Ahead HSL")
        self.ercot_out["Load"]["Total Area"]["Forecasted Next Day"] = timeseries
        timeseries, lines = self.ercot_html_parse(lines, 1, 2, "ENDING_ENDING")
        self.ercot_out["Load"]["Total Area"]["High Sustai"
                                                    "nable Limit"] = timeseries

    def total_gen_get(self):
        gen = urllib2.urlopen(self.DATA_TYPES["Total Generation"]["Uri"])
        lines = gen.readlines()
        gen.close()
        self.ercot_out["Generation"]["Total"] = {}
        lines = self.ercot_strip(lines, self.total_gen_line_fix)
        timeseries, lines = self.ercot_html_parse(lines, 0, 1, "LASL")
        self.ercot_out["Generation"]["Total"]["High Ancillary "
                                                  "Service Limit"] = timeseries
        timeseries, lines = self.ercot_html_parse(lines, 0, 1, "ENDING_ENDING")
        self.ercot_out["Generation"]["Total"]["Low Ancillary "
                                                  "Service Limit"] = timeseries

    def wind_gen_get(self):
        gen = urllib2.urlopen(self.DATA_TYPES["Wind Generation"]["Uri"])
        lines = gen.readlines()
        gen.close()
        self.ercot_out["Generation"]["Wind"] = {}
        lines = self.ercot_strip(lines, lambda x: x[0:len(x)-1])
        timeseries, lines = self.ercot_html_parse(lines, 0, 1, "Day-Ahead")
        self.ercot_out["Generation"]["Wind"]["High Sustainable "
                                                  "Limit Today"] = timeseries
        timeseries, lines = self.ercot_html_parse(lines, 1, 2, "Actual")
        self.ercot_out["Generation"]["Wind"]["High Sustainable "
                                                  "Limit Next Day"] = timeseries
        timeseries, lines = self.ercot_html_parse(lines, 0, 1, "ENDING_ENDING")
        self.ercot_out["Generation"]["Wind"]["Actual"] = timeseries

    def SPP_get(self):
        spp = urllib2.urlopen(self.DATA_TYPES["Actual SPP"]["Uri"])
        lines = spp.readlines()
        spp.close()
        while "th class=" not in lines[0]:
            lines.pop(0)
        while "</tr>" not in lines[len(lines)-1]:
            lines.pop()
        giantstr = ""
        for line in lines:
            giantstr += line
        lines = giantstr.split("</tr>\r\n\t<tr>")
        intermed_out = []
        for line in lines:
            temp = line.replace("\n", "")
            temp = temp.replace("\t", "")
            temp = re.sub(r'\<.*?\>', '', temp)
            intermed_out.append(temp)
        fix = intermed_out.pop(0)
        fix = fix.split('\r\r')
        intermed_out.insert(0, fix[1])
        intermed_out.insert(0, fix[0])
        lines = []
        for line in intermed_out:
            lines.append(line.strip().split('\r'))

        columns = lines.pop(0)[2:]
        for place in columns:
            self.ercot_out["SPP"][place] = { "Actual": [] }
        for line in lines:
            pdate = line.pop(0)
            ptime = line.pop(0)
            if "2400" in ptime:
                pdate = (int(time.mktime(time.strptime(pdate, "%m/%d/%Y"))) + 
                                                                        86400)
                pdate = time.strftime("%m/%d/%Y", time.gmtime(pdate))
                ptime = "0000"
            ptime = pdate + " " + ptime
            ptime = time.strptime(ptime, "%m/%d/%Y %H%M")
            ptime = int(time.mktime(ptime))
            for x in range(0, len(line)):
                point = [ptime, float(line[x])]
                self.ercot_out["SPP"][columns[x]]["Actual"].append(point)

    def real_LMP_get(self):
        lmp = urllib2.urlopen(self.DATA_TYPES["Actual LMP"]["Uri"])
        lines = lmp.readlines()
        lmp.close()
        intermed_out = []
        while "Last Updated" not in lines[0]:
            lines.pop(0)
        while "</tr>" not in lines[len(lines)-1]:
            lines.pop()
        giantstr = ""
        for line in lines:
            giantstr += line
        giantstr = giantstr.replace(" ", "")
        giantstr = re.sub(r'\<.*?\>', ' ', giantstr)
        intermed_out = giantstr.strip().split("    ")
        intermed_out.pop(0)
        ptime = intermed_out.pop(0).split("&nbsp;")[1]
        ptime = time.strptime(ptime, "%b%d,%Y%H:%M:%S")
        ptime = int(time.mktime(ptime))
        intermed_out.pop(0)
        for line in intermed_out:
            line = line.split("  ")
            point = [ptime, float(line[1])]
            self.ercot_out["LMP"][line[0]] = {"Actual": [point]}
    
    def forecast_SPP_get(self):
        texas_today = dtutil.now("America/Chicago")
        ptime = texas_today.strftime("%Y%m%d")
        url = self.DATA_TYPES["Forecasted SPP"]["Uri"].replace("<DATE HERE>",
                                                                         ptime)
        print(url)
        SPP = urllib2.urlopen(url)
        lines = SPP.readlines()
        SPP.close()
        while 'td class="headerValue' not in lines[0]:
            lines.pop(0)
        while "</tr>" not in lines[len(lines)-1]:
            lines.pop()
        giantstr = ""
        for line in lines:
            giantstr += line
        lines = giantstr.split("</tr>\r\r\n\t\t\t\t\t\t\t<tr>")
        intermed_out = []
        for line in lines:
            temp = line.replace("\n", "")
            temp = temp.replace("\t", "")
            temp = temp.replace("\r\r", " ")
            temp = re.sub(r'\<.*?\>', '', temp)
            temp = temp.strip().split()
            intermed_out.append(temp)
        lines = intermed_out
        columns = intermed_out.pop(0)[4:]
        for place in columns:
            if place not in self.ercot_out["SPP"].keys():
                self.ercot_out["SPP"][place] = { "Forecasted": [] }
            else:
                self.ercot_out["SPP"][place]["Forecasted"] = []
        for line in lines:
            line.pop(0)
            ptime = line.pop(0) + ":00"
            if "24" in ptime:
                ptime = self.parse_time("00:00", 1)
            else:
                ptime = self.parse_time(ptime, 0)
            for x in range(0, len(line)):
                point = [ptime, float(line[x])]
                self.ercot_out["SPP"][columns[x]]["Forecasted"].append(point)

                                            
       
     
    def total_gen_line_fix(self, lines):
        temp_out = []
        for x in range(0, len(lines), 2):
            temp_out.append(lines[x].replace("\r\n", "") + lines[x+1])
        return temp_out

    def ercot_html_parse(self, lines, inoff, nextoff, stop_str):
        timeseries = []
        while stop_str not in lines[0][0]:
            point = []
            temp = lines.pop(0)
            if '00:00' in temp[1]:
                point.append(self.parse_time(temp[1], nextoff))
            else:
                point.append(self.parse_time(temp[1], inoff))
            point.append(float(temp[2].replace(",","")))
            timeseries.append(point)
        leftoverlines = lines
        return (timeseries, leftoverlines)

    def ercot_strip(self, lines, custom_process):
        #cleans ercot html for processing
        intermed_out = []
        while "<area" not in lines[0]:
            lines.pop(0)
        while "</map>" not in lines[len(lines)-1]:
            lines.pop()
        lines = custom_process(lines)
        for line in lines:
            temp = line.split("title=")[1]
            temp = temp.split(" alt=")[0]
            temp = temp.replace('"', '')
            temp = temp.split(":", 1)
            temp += temp.pop().strip().split()
            intermed_out.append(temp)
        intermed_out += [["ENDING_ENDING"]] #sentinel for end
        return intermed_out

    def parse_time(self, time_str, dayoff):
        texas_today = dtutil.now("America/Chicago")
        texas_time = texas_today + datetime.timedelta(seconds=dayoff*86400)
        ptime = texas_time.strftime("%Y%m%d") + " " + time_str
        out = time.strptime(ptime, "%Y%m%d %H:%M")
        return int(time.mktime(out))

    def namer(self, data_type, location, valtype):
        if (valtype + " " + data_type) in self.DATA_TYPES.keys():
            return valtype + " " + data_type
        elif (location + " " + data_type) in self.DATA_TYPES.keys():
            return location + " " + data_type
        else:
            return "ERR_ERR_ERR"


    def setup(self, opts):
        self.lastLatests = {}
        self.update_frequency = 300
        scraped = self.scrape()
        namer = self.namer
        for data_type in scraped.keys():
            for location in scraped[data_type].keys():
                for valtype in scraped[data_type][location].keys():
                    path = "/" + data_type + "/" + location + "/" + valtype
                    temp = self.add_timeseries(path, "ERCOT" + data_type + 
                                location + valtype,
                             self.DATA_TYPES[namer(data_type, 
                                                location, valtype)]["Unit"], 
                                        data_type = "double", description =
                                                    valtype + " " + 
                                            self.DATA_TYPES[namer(data_type, 
                                        location, valtype)]["Description"] 
                                                      + " (" + location + ")")
                    temp['Metadata'] = { 'Location' : {'Country': 'USA', 'Area': 
                         'Texas', 'Uri': 
                            self.DATA_TYPES[namer(data_type, location, 
                              valtype)]["Uri"]}, 'Extra' : {'ISOName': 'ERCOT', 
                                   'ISOType': data_type, 'ISOSubType': location,
                                            'ISODataType': valtype }
                                }
                    temp['Properties']['Timezone'] = "America/Chicago"
                    self.lastLatests[path] = None
                    
                 
if __name__ == '__main__':
    a = ErcotDriver()
    b = a.scrape()
    print(b)
