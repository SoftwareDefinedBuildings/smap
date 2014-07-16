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
@author Jonathan Fuerst <jonf@itu.dk>
"""
import os, requests, __builtin__
from smap import actuate, driver
from smap.util import periodicSequentialCall
from smap.contrib import dtutil
from requests.auth import HTTPDigestAuth
import json
import time

from twisted.internet import threads

class IMT550C(driver.SmapDriver):
    def setup(self, opts):
        self.tz = opts.get('Metadata/Timezone', None)
        self.rate = float(opts.get('Rate', 5))
        self.ip = opts.get('ip', None)
        self.user = opts.get('user', None)
        self.password = opts.get('password', None)
        self.points0 = [
                          {"name": "temp", "unit": "F", "data_type": "double",
                            "OID": "4.1.13", "range": (-30.0,200.0),
                            "access": 4, "devtosmap": lambda x: x/10,
                            "smaptodev": lambda x: x*10,
                            "act_type": None}, # thermAverageTemp
                          {"name": "humidity", "unit": "%RH",
                           "data_type": "double", "OID": "4.1.14",
                            "range": (0,95), "access": 0,
                            "devtosmap": lambda x: x, "smaptodev": lambda x: x,
                            "act_type": "continuous"}, #thermRelativeHumidity
                          {"name": "hvac_state", "unit": "Mode",
                            "data_type": "long",
                            "OID": "4.1.2", "range": [0,1,2], "access": 4,
                            "devtosmap":  lambda x: {1:0, 2:0, 3:1, 4:1, 5:1, 6:2, 7:2, 8:0, 9:0}[x],
                            "smaptodev":  lambda x: {x:x}[x],
                            "act_type": "discrete"}, # thermHvacState
                          {"name": "fan_state", "unit": "Mode", "data_type": "long",
                            "OID": "4.1.4", "range": [0,1], "access": 4,
                            "devtosmap":  lambda x: {0:0, 1:0, 2:1}[x],
                            "smaptodev": lambda x: {x:x}[x],
                            "act_type": "discrete"}, # thermFanState
                          {"name": "temp_heat", "unit": "F", "data_type": "double",
                            "OID": "4.1.5", "range": (45.0,95.0), "access": 6,
                            "devtosmap": lambda x: x/10, "smaptodev": lambda x: x*10,
                            "act_type": "continuous"}, #thermSetbackHeat
                          {"name": "temp_cool", "unit": "F", "data_type": "double",
                            "OID": "4.1.6",
                            "range": (45.0,95.0), "access": 6,
                            "devtosmap": lambda x: x/10, "smaptodev": lambda x: x*10,
                            "act_type": "continuous"}, #thermSetbackCool
                          {"name": "hold", "unit": "Mode",
                            "data_type": "long", "OID": "4.1.9",
                            "range": [0,1], "access": 6,
                            "devtosmap": lambda x: {1:0, 2:1, 3:0}[x],
                            "smaptodev": lambda x: {0:1, 1:2}[x],
                            "act_type": "discrete"}, # hold/override
                          {"name": "override", "unit": "Mode",
                            "data_type": "long", "OID": "4.1.9",
                            "range": [0,1], "access": 6,
                            "devtosmap": lambda x: {1:0, 3:1, 2:0}[x],
                            "smaptodev": lambda x: {0:1, 1:3}[x],
                            "act_type": "discrete"}, # hold/override                          
                          {"name": "hvac_mode", "unit": "Mode", "data_type": "long",
                            "OID": "4.1.1", "range": [0,1,2,3],
                            "access": 6,
                            "devtosmap": lambda x: x-1,
                            "smaptodev": lambda x: x+1,
                            "act_type": "discrete"}, # thermHvacMode
                          {"name": "fan_mode", "unit": "Mode", "data_type": "long",
                            "OID": "4.1.3", "range": [1,2,3], "access": 6,
                            "devtosmap": lambda x: x, "smaptodev": lambda x: x,
                            "act_type": "discrete"} # thermFanMode
                       ]
        for p in self.points0:
            self.add_timeseries('/' + p["name"], p["unit"],
                data_type=p["data_type"], timezone=self.tz)
            if p['access'] == 6:
                if p['act_type'] == 'discrete':
                    setup={'model': 'discrete', 'ip':self.ip, 'states': p['range'],
                        'user': self.user, 'password': self.password, 'OID': p['OID'],
                        'devtosmap': p['devtosmap'], 'smaptodev': p['smaptodev']}
                    act = DiscreteActuator(**setup)
                    self.add_actuator('/' + p['name'] + '_act', p['unit'], act, data_type = p['data_type'], write_limit=5)
                elif p['act_type'] == 'continuous':
                    setup={'model': 'continuous', 'ip':self.ip, 'range': p['range'],
                        'user': self.user, 'password': self.password, 'OID': p['OID'],
                        'devtosmap': p['devtosmap'], 'smaptodev': p['smaptodev']}
                    act = ContinuousActuator(**setup)
                    self.add_actuator('/' + p['name'] + '_act', p['unit'], act,
                        data_type = p['data_type'], write_limit=5)
                elif p['act_type'] == 'continuousInteger':
                    setup={'model': 'continuousInteger', 'ip':self.ip, 'range': p['range'],
                        'user': self.user, 'password': self.password, 'OID': p['OID'],
                        'devtosmap': p['devtosmap'], 'smaptodev': p['smaptodev']}
                    act = ContinuousIntegerActuator(**setup)
                    self.add_actuator('/' + p['name'] + '_act', p['unit'], act,
                        data_type = p['data_type'], write_limit=5)
                else:
                    print "sth is wrong here"

    def start(self):
        # call self.read every self.rate seconds
        periodicSequentialCall(self.read).start(self.rate)

    def read(self):
        for p in self.points0:
            url = 'http://%s/get?OID%s' % (self.ip, p["OID"])
            r = requests.get(url, auth=HTTPDigestAuth(self.user, self.password))
            val = r.text.split('=', 1)[-1]
            if p["data_type"] == "long":
                self.add("/" + p["name"], p['devtosmap'](long(val)))
            else:
                self.add("/" + p["name"], p['devtosmap'](float(val)))

class ThermoActuator(actuate.SmapActuator):

    def __init__(self, **opts):
        self.ip = opts['ip']
        self.user = opts['user']
        self.password = opts['password']
        self.url = 'http://' + self.ip
        self.OID = opts['OID']
        self.devtosmap = opts['devtosmap']
        self.smaptodev = opts['smaptodev']

    def get_state(self, request):
        r = requests.get(self.url+"/get?OID"+self.OID+"=",
            auth=HTTPDigestAuth(self.user, self.password))
        rv = self.devtosmap(float(r.text.split('=', 1)[-1]))
        return self.parse_state(rv)

    def set_state(self, request, state):
        payload = {"OID"+self.OID: int(self.smaptodev(state)), "submit": "Submit"}
        r = requests.get('http://'+self.ip+"/pdp/",
            auth=HTTPDigestAuth(self.user, self.password), params=payload)
        return self.devtosmap(state)

class DiscreteActuator(ThermoActuator, actuate.NStateActuator):
    def __init__(self, **opts):
        actuate.NStateActuator.__init__(self, opts['states'])
        ThermoActuator.__init__(self, **opts)

class ContinuousActuator(ThermoActuator, actuate.ContinuousActuator):
    def __init__(self, **opts):
        actuate.ContinuousActuator.__init__(self, opts['range'])
        ThermoActuator.__init__(self, **opts)

class ContinuousIntegerActuator(ThermoActuator, actuate.ContinuousIntegerActuator):
    def __init__(self, **opts):
        actuate.ContinuousIntegerActuator.__init__(self, opts['range'])
        ThermoActuator.__init__(self, **opts)
