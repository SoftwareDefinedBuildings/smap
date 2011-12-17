
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

