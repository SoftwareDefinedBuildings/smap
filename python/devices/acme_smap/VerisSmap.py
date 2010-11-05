
import sys
import logging
import time
import signal
import copy

signal.signal(signal.SIGINT, signal.SIG_DFL)
sys.path.append('../../lib')

import SmapRefImpl
import ACmeDriver


class VerisMeterCollection(SmapRefImpl.Collection):
    """Handle requests for sensor data"""
    def __init__(self):
        # only has one meter per channel
        SmapRefImpl.Collection.__init__(self, {'0' : self})
    
    def do_GET(self, request):
        if len(request['path']) == 0:
            return self.resources.keys()
        elif len(request['path']) == 1:
            return ["reading",
                    "formatting",
                    "parameter",
                    "profile"]
        elif len(request['path']) == 2:
            resource = request['path'][1]
            channe_idx = int(request['full_path'][1])
            sensor_idx = int(request['path'][0])
        else: return None
        
        if resource == "reading":
            if sensor_idx == 0:
                # default metering interface
                # other sensors are available through the "sensing" interface
                return { "$schema" : {"$ref" : "http://webs.cs.berkeley.edu/schema/reading.json"},
                         # "PowerFactor" : veris_poller.instantaneous['PowerFactor'][channe_idx],
                         "RateInstantaneous" : veris_poller.instantaneous['Power'][channe_idx],
                         "SummationDelivered" : veris_poller.metervals['Summation'][channe_idx],
                         "SummationInterval"  : int(veris_poller.summation_interval),
                         "ReadingTime" : int(veris_poller.last_summation[channe_idx])
                         }
        elif resource == "formatting":
            return { "$schema" : {"$ref" : "http://webs.cs.berkeley.edu/schema/format.json"},
                     "UnitofMeasure" : "kW",
                     "UnitofTime" : "second",
                     "Divisor" : 24,
                     "MeterType" : "electric"}
        elif resource == "parameter":
            return { "$schema" : {"$ref" : "http://webs.cs.berkeley.edu/schema/parameter.json"},
                     "SamplingPeriod" : veris_poller.summation_interval,
                     "UnitofTime" : "second",
                     "Settings" : {}}
        elif resource == "profile":
            rv = []
            for (m,i,t) in profileData:
                rv.append( {
                        'PowerFactor' : i['PowerFactor'][channe_idx],
                        'RateInstantaneous' : i['Power'][channe_idx],
                        'SummationDelivered' : m['Summation'][channe_idx],
                        'SummationInterval' : int(veris_poller.summation_interval),
                        'ReadingTime' : int(t[channe_idx]) } )
            return rv

            


class VerisSensorCollection(SmapRefImpl.Collection):
    def __init__(self):
        # only has one meter per channel
        SmapRefImpl.Collection.__init__(self, {})
    
    def do_GET(self, request):
        return []

class VerisActuatorCollection(SmapRefImpl.Collection):
    """Handle requests for actuations"""
    def __init__(self):
        # only has one meter per channel
        SmapRefImpl.Collection.__init__(self, {'0' : self})
    
    def do_GET(self, request):
        if len(request['path']) == 0:
            return self.resources.keys()
        elif len(request['path']) == 1:
            return ["onff",
                    "setpoint",
                    "bonds",
                    "other"]
        elif len(request['path']) == 2:
            resource = request['path'][1]
            channe_idx = int(request['full_path'][1])
            sensor_idx = int(request['path'][0])
        else: return None
        
        if resource == "onoff":
            return { "$schema" : {"$ref" : "todo"},
                     "State" : "todo"
                     }
        elif resource == "setpoint":
            return { "setpoint" : "todo"}
        elif resource == "bonds":
            return { "bonds" : "todo"}
        elif resource == "other":
            return { "bonds" : "todo"}
    
    def do_POST(self, request):
        print "ACTUATED"
        print request['path'], request['full_path']
        if len(request['path']) == 2:
            if request['path'][1] == 'onoff':
                # print request
                req = request['data']
                channe_idx = int(request['full_path'][1])
                if not req.has_key('State'):
                    self.logger.warn("invalid report request")
                else:
                    print "INNNNNNNNNNNNNNN"
                    state = req['State']
                    veris_poller.actuate(channe_idx, state)
                    return state
        return None

class ChannelCollection(SmapRefImpl.Collection):
    """ A class which services requests for a particular meter"""
    def __init__(self):
        SmapRefImpl.Collection.__init__(self, {'sensor' : VerisSensorCollection(),
                                               'meter'  : VerisMeterCollection(),
                                               'actuator'  : VerisActuatorCollection() })



class ContextCollection(SmapRefImpl.Collection):
    def __init__(self):
        SmapRefImpl.Collection.__init__(self, {'device'  :  self,
                                               'meta'     : self,
                                               'location' : self})
    
    context = {"device" : {
        "$schema" : {"$ref" : "http://webs.cs.berkeley.edu/schema/context/device.json"},
        "Type" : "Plug-load electric meter",
        "Make" : "Berkeley ACme",
        "Model" : "ACme X2",
        "Specs" : []
        },
        "location" : {
            "$schema" : {"$ref" : "http://webs.cs.berkeley.edu/schema/context/location.json"},
        },
        "meta" : {
        "$schema" : {"$ref" : "http://webs.cs.berkeley.edu/schema/context/meta.json"},
        }}
    def do_GET(self, request):
        print request['path'][0]
        
        if len(request['path']) == 0:
            return ['device', 'meta', 'location']
        elif self.context.has_key(request['path'][0]):
            return self.context[request['path'][0]]
	elif request['path'][0] == '*':
	    return self.context
        else:
            return None

class StatusCollection(SmapRefImpl.Collection):
    def __init__(self):
        SmapRefImpl.Collection.__init__(self, {'status' : self})
    
    def do_GET(self, request):
        return {
        	"PubID" : "1463794070",
        	"name":"data_stream",
            "$schema" : {"$ref" : "http://webs.cs.berkeley.edu/schema/status.json"},
            "LocalTime" : int(time.time()),
            "Status"    : 0
            }

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    veris_poller = ACmeDriver.ACmeDriver()

    
    profileData = []
    def addProfileData():
        metervals = copy.deepcopy(veris_poller.metervals)
        instantaneous = copy.deepcopy(veris_poller.instantaneous)
        last_summation = copy.deepcopy(veris_poller.last_summation)
        profileData.append((metervals, instantaneous, last_summation))
        if len(profileData) > 60:
            profileData.pop(0)
    veris_poller.addChangeHandler(addProfileData)
    
    chan_collection = ChannelCollection()
    
    reports = SmapRefImpl.ReportingCollection()
    
    collect = SmapRefImpl.Collection()
    veris_poller.setCollect(collect, chan_collection)
    veris_poller.start()
    
    root = SmapRefImpl.Collection( {"data"      : collect,
                                    "reporting" : reports,
                                    "context"   : ContextCollection(),
                                    "status"    : StatusCollection(),
                                    } )

    
    
    reports.root = root
    
    impl = SmapRefImpl.RefImpl(root)
    impl.start()
    reports.start()
