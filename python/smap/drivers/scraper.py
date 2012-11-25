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

from smap.driver import SmapDriver
from smap.util import periodicSequentialCall

urllib2.install_opener(urllib2.build_opener())

class ScraperDriver(SmapDriver):
    """Periodically republish scraped data as an sMAP feed. The driver that 
    extends this needs to define a scrape method that will be used by update
    and a special setup method with a special attr as defined below. Examples of
    setup methods that work automatically can be found in many of the iso
    scrapers, like pjm.py.
    """

    def scrape(self):
        """Implemented by a subclass. This should scrape data and return a dict 
        that is used by setup to create the timeseries and by update to add data 
        to the timeseries"""

        """ Dict format is as follows: 
            {"data_type": {"location1": {"value_type1": timeseries, 
                                         "value_type2": timeseries, ...}
                            "location2": {"value_type1": timeseries, ...} },
             "data_type2": {"location1": {"value_type1": timeseries, 
                                          "value_type2": timeseries, ...}
                            "location2": {"value_type1": timeseries, ...} } }

            timeseries of format [[1, 1], [2, 2], [3, 3], etc.]
            This will create feeds with paths like:
            /PrefixFromIni/data_type/location/value_type
            For example:
            /PJM/LMP/112 WILT/FiveMin
        """
        return {}

    def update(self):
        """This automatically updates/adds timeseries data, assuming that the
        dict returned by the scrape method is formatted as above."""
        # Note that the scrape method is in a try/except clause here in order to
        # allow the driver to recover if there is an error on pageload. However,
        # DO NOT place the call to self.scrape() in setup() inside a try/except
        # clause. setup() should only complete successfully if all of the
        # data is able to be loaded (since timeseries creation depends on an
        # initial fetch of data). If errors are handled elsewhere (ie in the
        # scrape() method), nasty things like partial setup of timeseries could
        # occur.
        try:
            scraped = self.scrape()
        except urllib2.URLError:
            pass
        except urllib2.HTTPError:
            pass
        except IOError:
            pass
        else:
            for data_type in scraped.keys():
                for location in scraped[data_type].keys():
                    for valtype in scraped[data_type][location].keys():
                        timeseries = scraped[data_type][location][valtype]
                        path = "/" + data_type + "/" + location + "/" + valtype
                        for pair in timeseries:
                            if pair[0] <= self.lastLatests[path]:
                                continue
                            self.add(path, pair[0], pair[1])
                            self.lastLatests[path] = pair[0]

    def setup(self, opts):
        """This can be done almost completely automatically using code similar 
        to that used in the ISO scrapers. See the setup method in pjm.py for an 
        example."""
        # WARNING: DO NOT put the call to self.scrape() in a try/except clause
        # here. Doing so can cause nasty things like partial timeseries setup
        # since complete data load is essential to setup. More information is in
        # the note in update()
        # Effectively, you should allow all errors to propagate in this method.

        # User needs to define:

        # lastLatests, a dict used to prevent resubmission of duplicates
        # self.lastLatest = {}, each item is (path: None) by default

        # update_frequency of the feeds, in seconds
        # self.update_frequency = 3600 

        # standard timeseries add or automatic version as noted above.
        pass
    
    def start(self):
        periodicSequentialCall(self.update).start(self.update_frequency)
