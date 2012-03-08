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
"""

import time
import urllib2

from zope.interface import implements

from smap.driver import SmapDriver
from smap.util import periodicCallInThread

urllib2.install_opener(urllib2.build_opener())

class CaIsoDriver(SmapDriver):
    """Periodically scrape the feed from the CAISO site and republish
    it as a sMAP feed.
    """

    def update(self):
        object_ = {}
        try:
            fh = urllib2.urlopen('http://www.caiso.com/outlook/systemstatus.csv')
            for line in fh.readlines():
                kv = line.strip().split(',')
                object_[kv[0]] = kv[1]
        except urllib2.URLError:
            pass
        except urllib2.HTTPError:
            pass
        except IOError:
            pass
        else:
            thisTime = int(time.mktime(time.strptime(object_['Produced'])))
            if self.lastProduced == None or self.lastProduced != thisTime:
                print "Updated reading"
                self.t.add(thisTime, int(object_['Actual Demand']))
                self.lastProduced = thisTime
            fh.close()

    def setup(self, opts):
        self.lastProduced = None
        self.t = self.add_timeseries('/CA', 'caisomain', 'mWh', 
                                     description='Total demand from the CA ISO')
        self.t['Metadata'] = {
            'Location' : {'State': 'CA', 'Country' : 'USA', 'Area': 'CA ISO',
                          'Uri' : 'http://www.caiso.com/outlook/systemstatus.csv'},
            }

    def start(self):
        periodicCallInThread(self.update).start(60 * 5)
