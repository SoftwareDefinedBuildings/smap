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
from smap.driver import SmapDriver
from smap.util import periodicSequentialCall
from smap.contrib import dtutil
import requests
import json
from smap import actuate
import time

from twisted.internet import threads

class CT80(SmapDriver):
    def setup(self, opts):
        self.tz = opts.get('Timezone', 'America/Los_Angeles')
        self.rate = float(opts.get('Rate', 1))
        self.ip = opts.get('ip', None)
         
        self.points0 = [
                         {"name": "temp", "unit": "F", "data_type": "double"},
                         {"name": "tmode", "unit": "Mode", "data_type": "long"},
                         {"name": "fmode", "unit": "Mode", "data_type": "long"},
                         {"name": "override", "unit": "Mode", "data_type": "long"},
                         {"name": "hold", "unit": "Mode", "data_type": "long"},
                         {"name": "t_heat", "unit": "F", "data_type": "double"},
                         {"name": "program_mode", "unit": "Mode", "data_type": "long"}
                       ]
        for p in self.points0:
            self.add_timeseries('/' + p["name"], p["unit"], data_type=p["data_type"], timezone=self.tz)

        # points not in the root resource
        self.add_timeseries('/humidity', '%RH', data_type="double")

        self.actuators = [
            {"name": "t_heat", "act_type": "continuous", "unit": "F", "data_type": "double", "range": (40,100)},
            {"name": "tmode", "act_type": "discrete", "unit": "F", "data_type": "double", "states": [0,1]},
            {"name": "fmode", "act_type": "discrete", "unit": "F", "data_type": "double", "states": [0,1]},
            {"name": "override", "act_type": "discrete", "unit": "F", "data_type": "double", "states": [0,1]},
            {"name": "hold", "act_type": "discrete", "unit": "F", "data_type": "double", "states": [0,1]},
            {"name": "program_mode", "act_type": "discrete", "unit": "F", "data_type": "double", "states": [0,1]},
          ]
        
        setup = {'ip': self.ip}
        for a in self.actuators:
            setup["name"] = a["name"]
            if a["act_type"] == "discrete":
                setup["states"] = a["states"]
                act = DiscreteActuator(**setup)
            elif a["act_type"] == "continuous":
                setup["range"] = a["range"]
                act = ContinuousActuator(**setup)
            else:
                print 'invalid actuator type'
            self.add_actuator("/" + a["name"] + "_act", a["unit"], act, data_type=a["data_type"], write_limit=5)

    def start(self):
        # call self.read every self.rate seconds
        periodicSequentialCall(self.read).start(self.rate)

    def read(self):
        url = 'http://' + self.ip + "/tstat"
        r = requests.get(url)
        vals = json.loads(r.text)
         
        for p in self.points0:
            self.add('/' + p["name"], vals[p["name"]])

        r = requests.get(url + '/humidity')
        val = json.loads(r.text)
        self.add('/humidity', val['humidity'])

class _CT80Actuator(actuate.ContinuousActuator):
    def __init__(self, **opts):
        self.ip = opts.get('ip', None)
        self.name = opts.get('name', None)
        self.url = 'http://' + self.ip + '/tstat/' + self.name

    def get_state(self, request):
        r = requests.get(self.url)
        rv = json.loads(r.text)
        return self.parse_state(rv)
 
    def set_state(self, request, state):
        payload = '{"' + self.name + '": ' + str(state) + '}'
        r = requests.post(self.url, data=payload)
        time.sleep(2)
        return state 

class DiscreteActuator(_CT80Actuator, actuate.NStateActuator):
    def __init__(self, **opts):
        actuate.NStateActuator.__init__(self, opts['states'])
        _CT80Actuator.__init__(self, **opts)

class ContinuousActuator(_CT80Actuator, actuate.ContinuousActuator):
    def __init__(self, **opts):
        actuate.ContinuousActuator.__init__(self, opts['range'])
        _CT80Actuator.__init__(self, **opts) 

