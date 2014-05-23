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
@author Tyler Hoyt <thoyt@berkeley.edu>
"""
import requests
from smap import actuate, driver
from smap.util import periodicSequentialCall
import xml.etree.ElementTree as ET

class Enlighted(driver.SmapDriver):
    def setup(self, opts):
        self.tz = opts.get('Metadata/Timezone', None)
        self.rate = float(opts.get('Rate', 5))
        self.ip = opts.get('ip', None)
        self.username = opts.get('username')
        self.password = opts.get('password')
        self.api = EnlightedAPI(self.ip, auth=(self.username, self.password))
        # Todo: how to get the sensor and zone metadata automatically? 
        self.sensor_ids = [1]
        for sensor_id in self.sensor_ids:
            api = [{'path': '/sensor_%s/dim_level' % sensor_id, 'unit': '%'},
                   {'path': '/sensor_%s/occupancy_status' % sensor_id, 'unit': 'state'},
                   {'path': '/sensor_%s/time_since_last_occupancy' % sensor_id, 'unit': 'sec'}]
            for resource in api: 
                self.add_timeseries(resource['path'], resource['unit'], data_type="long")

            setup = {'ip': self.ip, 'sensor_id': sensor_id, 'range': [0,100], 'api': self.api}
            act = ContinuousIntegerActuator(**setup)
            self.add_actuator('/sensor_%s/dim_level_act' % sensor_id,
                  '%', act, data_type='long', write_limit=1)

    def start(self):
        periodicSequentialCall(self.read).start(self.rate)

    def read(self):
        for sensor_id in self.sensor_ids:
            self.add('/sensor_%s/dim_level' % sensor_id, 
                self.api.getSensorDimLevel(sensor_id))
            self.add('/sensor_%s/occupancy_status' % sensor_id, 
                self.api.getSensorOccupancyStatus(sensor_id))
            self.add('/sensor_%s/time_since_last_occupancy' % sensor_id, 
                self.api.getSensorLastOccupancySeen(sensor_id))
    
class Actuator(actuate.SmapActuator):
    def __init__(self, **opts):
        self.ip = opts['ip']
        self.sensor_id = opts['sensor_id']
        self.api = opts['api']

    def get_state(self, request):
        return self.api.getSensorDimLevel(self.sensor_id)

    def set_state(self, request, state):
        return self.api.setSensorDimLevel(self.sensor_id, state, 10000)

class ContinuousIntegerActuator(Actuator, actuate.ContinuousIntegerActuator):
    def __init__(self, **opts):
        actuate.ContinuousIntegerActuator.__init__(self, opts["range"])
        Actuator.__init__(self, **opts)

class EnlightedAPI(object):
    def __init__(self, ip, auth=None):
        self.ip = ip
        self.session = requests.session()
        self.session.headers.update({'Content-Type':'application/xml'})
        self.session.verify = False
        self.session.auth = auth
       
    def parse(self, msg):
        rv = {}
        root = ET.fromstring(msg)
        for child in root:
            rv[child.tag] = int(child.text)
        if rv['status'] == 0: return rv['msg']

    def getSensorDimLevel(self, sensor_id):
        url = 'https://%s/hvac/services/sensor/getDimLevel/id/%s' % (self.ip, sensor_id)
        r = self.session.get(url)
        return self.parse(r.content)

    def setSensorDimLevel(self, sensor_id, amount, time):
        url = 'https://%s/hvac/services/sensor/setDimLevel/id/%s/%s/%s' % (self.ip, sensor_id, amount, time)
        r = self.session.get(url)
        return self.parse(r.content)

    def getSensorLastOccupancySeen(self, sensor_id):
        url = 'https://%s/hvac/services/sensor/getLastOccupancySeen/id/%s' % (self.ip, sensor_id)
        r = self.session.get(url)
        return self.parse(r.content)

    def getSensorOccupancyStatus(self, sensor_id):
        url = 'https://%s/hvac/services/sensor/getOccupancyStatus/id/%s' % (self.ip, sensor_id)
        r = self.session.get(url)
        return self.parse(r.content)

    def getZoneAvgDimLevel(self, zone_id):
        url = 'https://%s/hvac/services/zone/getAvgDimLevel/id/%s' % (self.ip, zone_id)
        r = self.session.get(url)
        return self.parse(r.content)

    def setZoneDimLevel(self, zone_id, amount, time):
        url = 'https://%s/hvac/services/zone/setDimLevel/id/%s/%s/%s' % (self.ip, zone_id, amount, time)
        r = self.session.get(url)
        return self.parse(r.content)

    def getZoneLastOccupancySeen(self, zone_id):
        url = 'https://%s/hvac/services/zone/getLastOccupancySeen/id/%s' % (self.ip, zone_id)
        r = self.session.get(url)
        return self.parse(r.content)

    def getZoneOccupancyStatus(self, zone_id):
        url = 'https://%s/hvac/services/zone/getOccupancyStatus/id/%s' % (self.ip, zone_id)
        r = self.session.get(url)
        return self.parse(r.content)

if __name__=='__main__':
    e = EnlightedAPI("10.4.10.139")
    print e.getSensorDimLevel(1)
    print e.setSensorDimLevel(1,5,1)
    print e.getSensorLastOccupancySeen(1)
    print e.getSensorOccupancyStatus(1)
    #print e.getZoneAvgDimLevel(2)
    #print e.setZoneDimLevel(2,60,1)
    #print e.getZoneLastOccupancySeen(2)
    #print e.getZoneOccupancyStatus(2)
