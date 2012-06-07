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

"""
TODO:
What if a timeseries has multiple points to be added at once?
Keeping track of update times for different timeseries?
"""
                                                                                
import time
import urllib2

from zope.interface import implements

from smap.driver import SmapDriver
from smap.util import periodicCallInThread

urllib2.install_opener(urllib2.build_opener())

class ScraperDriver(SmapDriver):
    """Periodically republish scraped data as an sMAP feed. Driver that 
    implements this needs to define a scrape method that will be used by update
    and a special setup method with a special attr as defined below.
    """

    def scrape(self):
        """Implemented by a subclass. This should scrape data and return a dict 
        that is used by setup to create the timeseries and by update to add data 
        to the timeseries"""

        """ Dict format is as follows: 
            {"data_type": {"location1": {"value_type1": value, "value_type2":
                                            value, ...}
                            "location2": {"value_type1": value, ...} },
             "data_type2": {"location1": {"value_type1": value, "value_type2":
                                            value, ...}
                            "location2": {"value_type1": value, ...} } }

            This will create feeds with paths like:
            /PrefixFromIni/data_type/location/value_type
            For example:
            /PJM/LMP/112 WILT/FiveMin
        """
        return {}

    def update(self):
        """V2NOTES: this will need to handle multiple timeseries"""
        try:
            scraped = self.scrape()
        except urllib2.URLError:
            pass
        except urllib2.HTTPError:
            pass
        except IOError:
            pass
        else:
            time = scraped[1]
            scraped = scraped[0]
            for data_type in scraped.keys():
                for location in scraped[data_type].keys():
                    for valtype in scraped[data_type][location].keys():
                        self.add("/" + data_type + "/" + location + "/" + 
                                valtype, time, 
                                scraped[data_type][location][valtype])

    def setup(self, opts):
        """V2NOTES: This will probably have to fetch data once to generate the
        data for each timeseries"""
        #User needs to define:
        #lastLatest used to prevent resubmission of duplicates
        #self.lastLatest = None
        #update_frequency of the feed, in seconds
        #self.update_frequency = 3600 
        #standard timeseries stuff
        #self.t = self.add_timeseries(...)
        #self.t['Metadata'] = {}
        pass
    
    def start(self):
        periodicCallInThread(self.update).start(self.update_frequency)
