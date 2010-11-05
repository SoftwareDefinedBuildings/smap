"""
"""
import sys
import logging
import time
import threading
import urllib2
import signal

sys.path.append("../../lib")

import smaplog
import SmapRefImpl

urllib2.install_opener(urllib2.build_opener())
signal.signal(signal.SIGINT, signal.SIG_DFL)

synced = False
profile = []

class UpdateThread(threading.Thread):
    def run(self):
        global profile
        lastProduced = None

        while True:
            logging.info("Updating meter reading")

            fh = urllib2.urlopen('http://www.caiso.com/outlook/systemstatus.csv')
            object = {}

            for line in fh.readlines():
                kv = line.strip().split(',')
                object[kv[0]] = kv[1]

            newReading = {
                '$schema' : {'$ref' : 'http://webs.cs.berkeley.edu/schema/meter/data/readings'},
                'RateInstantaneous' : object['Actual Demand'],
                'ReadingTime'  : int(time.mktime(time.strptime(object['Produced'])))
                }

            if len(profile) == 0 or \
                   (len(profile) > 0 and profile[-1]['ReadingTime'] != newReading['ReadingTime']):
                logging.info("Updated reading")
                profile.append(newReading);
                if len(profile) > 24 * 4:
                    profile.pop(0)

                global reporting
                reporting.push()
            
            fh.close()

            time.sleep(60 * 5)

class CaStatus:
    def do_GET(self, request):
        global synced, boot_time
        status = 1
        if synced:
            status = 0
        return { '$schema' : {'$ref' : 'http://webs.cs.berkeley.edu/schema/meter/status'},
                 'LocalTime' : int(time.time()),
                 "Uptime"    : int(time.time() - boot_time),
                 'Status'    : status }

class CaFormatting:
    def do_GET(self, request):
        return {'$schema' : {'$ref' : 'http://webs.cs.berkeley.edu/schema/meter/data/formatting'},
                'UnitofMeasure' : 'kW',
                'UnitofTime' : 'second',
                'MeterType' : 'electric',
                'Multiplier' : 1000, # CAISO numbers are in megawatts...
                }

class CaProfile:
    def do_GET(self, request):
        global profile
        return profile

class CaParameter:
    def do_GET(self, request):
        return {'$schema' : {'$ref' : 'http://webs.cs.berkeley.edu/schema/meter/data/parameter'},
                'SamplingPeriod' : 60 * 10,
                'UnitofTime' : 'second',
                'Settings' : {}
                }

class CaReading():
    def do_GET(self, request):
        global profile
        if len(profile) > 0:
            return profile[-1]
                
class ContextCollection(SmapRefImpl.Collection):
    def __init__(self):
        SmapRefImpl.Collection.__init__(self, {'device'  :  self,
                                               'meta'     : self,
                                               'location' : self})

    meter_context = {
        "device" : {
                "$schema" : {"$ref" : "http://webs.cs.berkeley.edu/schema/context/device.json"},
                "Type" : "Web proxy",
                "Make" : "CA ISO",
                "Model" : "Califorina Grid Demand",
                "Specs" : []
                },
        "location" : {
                "$schema" : {"$ref" : "http://webs.cs.berkeley.edu/schema/context/location.json"},
                },
        "meta" : {
                "$schema" : {"$ref" : "http://webs.cs.berkeley.edu/schema/context/meta.json"},
                }
        }

    def do_GET(self, request):
        if len(request['path']) == 0:
            return ['device', 'meta', 'location']
        elif self.meter_context.has_key(request['path'][0]):
            return self.meter_context[request['path'][0]]
        elif request['path'][0] == '*':
            return self.meter_context

class DataCollection(SmapRefImpl.Collection):
    def __init__(self):
        SmapRefImpl.Collection.__init__(self, {'reading'  : CaReading(),
                                               'parameter' : CaParameter(),
                                               'formatting': CaFormatting(),
                                               'profile'   : CaProfile()})

class MeterCollection(SmapRefImpl.Collection):
    def __init__(self):
        SmapRefImpl.Collection.__init__(self, {'0' : DataCollection() })

class ChannelSubCollection(SmapRefImpl.Collection):
    def __init__(self):
        SmapRefImpl.Collection.__init__(self, {"meter"  : MeterCollection()})

class ChannelCollection(SmapRefImpl.Collection):
    def __init__(self):
        SmapRefImpl.Collection.__init__(self, {'CA' : ChannelSubCollection()})

if __name__ == '__main__':
    global boot_time, reporting
    boot_time = time.time()
    smaplog.start_log()

    u = UpdateThread()
    u.start()

    reporting = SmapRefImpl.ReportingCollection(report_file='/var/smap/caiso-reports')

    c = SmapRefImpl.Collection( {"data"      : ChannelCollection(), 
                                 "reporting" : reporting,
                                 "context"   : ContextCollection(),
                                 "status"    : CaStatus()} )

    reporting.root = c
    ref = SmapRefImpl.RefImpl(c, port=8002)
    ref.start()
    reporting.start()

