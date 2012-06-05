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
from smap.util import periodicCallInThread

urllib2.install_opener(urllib2.build_opener())

class CSVScraperDriver(SmapDriver):
    """Periodically republish scraped data as an sMAP feed. Driver that 
    implements this needs to define a scrape method that will be used by update
    and a special setup method with a special attr as defined below.
    """

    def scrape(self):
        """this method scrapes data and returns it for use by the updater. It 
        should be of the format: [[time, value], [time2, value2], etc.] Times 
        should increase left to right and should be in seconds (web data seems 
        to be in ms). This should be implemented by the subclass. Update handles 
        ignoring duplicate data, so just return it all."""
        pass
        return [[1, 1], [2, 2]] #junk

    def update(self):
        try:
            timeseries = self.scrape()
        except urllib2.URLError:
            pass
        except urllib2.HTTPError:
            pass
        except IOError:
            pass
        else:
            while (self.lastLatest != None and len(timeseries) > 0 and 
                   timeseries[0][0] <= self.lastLatest):
                timeseries.pop(0)
            if len(timeseries) != 0:
                self.lastLatest = timeseries[len(timeseries)-1][0]
            else:
                print("no new data")
            for pair in timeseries:
                self.t.add(int(pair[0]), float(pair[1]))
                print(pair)

    def setup(self, opts):
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
