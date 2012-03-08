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

import re

from twisted.python import log
from twisted.internet import reactor
from twisted.web.client import getPage

from smap import util
from smap.driver import SmapDriver
from smap.contrib import dtutil

from BeautifulSoup import BeautifulSoup as bs

class Ted5000Driver(SmapDriver):
    def setup(self, opts):
        self.url = opts.get('Address')
        self.rate = int(opts.get('Rate', '60'))
        self.timezone = opts.get('Timezone', 'America/Los_Angeles')

        self.add_timeseries('/voltage', 'V')
        self.add_timeseries('/real_power', 'W')
        self.add_timeseries('/apparent_power', 'VA')

        self.set_metadata('/', {
            'Extra/Driver' : 'smap.drivers.ted.Ted5000Driver',
            })

    def start(self):
        util.periodicCallInThread(self.update).start(self.rate)
    
    def update(self):
        d = getPage(self.url)
        d.addCallback(self.process)

    def process(self, doc):
        doc = bs(doc)
        now = doc.livedata.gatewaytime
        now = dtutil.strptime_tz("%s %s %s %s %s %s" % (now.month.contents[0], 
                                                        now.day.contents[0], 
                                                        now.year.contents[0], 
                                                        now.hour.contents[0], 
                                                        now.minute.contents[0], 
                                                        now.maxsecond.contents[0]),
                                 "%m %d %y %H %M %S", tzstr=self.timezone)
        now = dtutil.dt2ts(now)
        self.add('/voltage', now, int(doc.livedata.voltage.total.voltagenow.contents[0]))
        self.add('/real_power', now, int(doc.livedata.power.total.powernow.contents[0]))
        self.add('/apparent_power', now, int(doc.livedata.power.total.kva.contents[0]))

