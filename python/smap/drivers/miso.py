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

from zope.interface import implements

from smap.driver import SmapDriver
from smap.drivers.csv_scraper import CSVScraperDriver
from smap.util import periodicCallInThread

urllib2.install_opener(urllib2.build_opener())

class MIsoDriver(CSVScraperDriver):
    """Periodically scrape the Wind Generation in MWh from the Midwest ISO 
    site and republish it as a sMAP feed.
    """

    """Sample csv data for quick ref:
    "TimestampGMT","DateTimeEST","HourEndingEST","Value"
    "1338757200000","Jun  3 2012  4:00PM","17","2459.73"
    "1338760800000","Jun  3 2012  5:00PM","18","2546.49"
    "1338764400000","Jun  3 2012  6:00PM","19","2402.53"
    """
    MISO_TYPES = {'Wind': {'Uri': 'https://www.midwestiso.org/ria/'
                           'windgenResponse.aspx?format=csv', 'Resource': 
                           '/Midwest', 'Label': 'misowind', 'Unit': 'MWh', 
                           'Data_type': 'double', 'Description': 'Wind '
                           'Generation from Midwest ISO', 'Metadata': {
                                'Location' : {'Country': 'USA', 'Area': 
                                'Midwest ISO', 'Uri': 'https://www.midwestiso.'
                                'org/ria/windgenResponse.aspx?format=csv'
                                    }
                                },
                            'Update_freq': 3600
                           }, 
                  'Other': {'http://www.com'}
                 }
    def scrape(self):
        """this method scrapes data and returns it for use by the updater. It 
        should be of the format: [[time, value], [time2, value2], etc.] Times 
        should increase left to right and should be in seconds (web data seems 
        to be in ms). This should be implemented by the subclass. Update handles 
        ignoring duplicate data, so just return it all."""

        timeseries = []
        fh = urllib2.urlopen(self.gentype_data['Uri'])
        lines = fh.readlines()
        fh.close()
        lines.pop(0) #removes the first line, which contains column headings
        for line in lines:
            temp = line.strip().replace('"', '').split(',')
            timeseries.append([int(temp[0])/1000, (temp[3])])
        return timeseries

    def setup(self, opts):
        self.gentype = opts.get('GenType')
        self.gentype_data = self.MISO_TYPES[opts.get('GenType')]
        gentype_data = self.gentype_data
        self.lastLatest = None #prevents duplicate data submission
        #update frequency in seconds
        self.update_frequency = gentype_data['Update_freq']
        self.t = self.add_timeseries(gentype_data['Resource'], 
                                     gentype_data['Label'],
                                     gentype_data['Unit'], 
                                     data_type=gentype_data['Data_type'], 
                                     description=gentype_data['Description'])
        self.t['Metadata'] = gentype_data['Metadata']
