#
# @author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
#

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
