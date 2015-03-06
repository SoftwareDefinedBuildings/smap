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
"""
This driver writes directly to the CT80, with all the quirks in its API. For a more thorough description,
look at ct80.py in this same folder
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

        self.set_metadata('/', {'Metadata/Device': 'Thermostat',
                                'Metadata/Model': 'CT80 RTA',
                                'Metadata/Driver': __name__})
         
        self.points = [
                         {"name": "temp", "unit": "F", "data_type": "double"},
                         {"name": "tmode", "unit": "Mode", "data_type": "long"},
                         {"name": "tstate", "unit": "State", "data_type": "long"},
                         {"name": "fmode", "unit": "Mode", "data_type": "long"},
                         {"name": "fstate", "unit": "State", "data_type": "long"},
                         {"name": "override", "unit": "Mode", "data_type": "long"},
                         {"name": "hold", "unit": "Mode", "data_type": "long"},
                         {"name": "t_heat", "unit": "F", "data_type": "double"},
                         {"name": "t_cool", "unit": "F", "data_type": "double"},
                         {"name": "program_mode", "unit": "Mode", "data_type": "long"}
                       ]

        self.actuators = [
            {"name": "t_heat", "act_type": "continuous", "unit": "F", "data_type": "double", "range": (40,100)},
            {"name": "t_cool", "act_type": "continuous", "unit": "F", "data_type": "double", "range": (40,100)},
            {"name": "tmode", "act_type": "discrete", "unit": "F", "data_type": "long", "states": [0,1,2,3]},
            {"name": "fmode", "act_type": "discrete", "unit": "F", "data_type": "long", "states": [0,1]},
            {"name": "override", "act_type": "discrete", "unit": "F", "data_type": "long", "states": [0,1]},
            {"name": "hold", "act_type": "discrete", "unit": "F", "data_type": "long", "states": [0,1]},
            {"name": "program_mode", "act_type": "discrete", "unit": "F", "data_type": "double", "states": [0,1]},
          ]

        # dictionary to translate the CT80 API endpoints into those defined by thermostat_functions.txt
        self.translate = {
                'temp': 'temp',
                'tmode': 'hvac_mode',
                'fmode': 'fan_mode',
                'fstate': 'fan_state',
                'override': 'override',
                'hold': 'hold',
                't_heat': 'temp_heat',
                't_cool': 'temp_cool',
                'tstate': 'hvac_state',
                'program_mode': 'program_mode'
                }

        ts = {}
        for p in self.points:
            ts[p['name']] = self.add_timeseries('/' + self.translate[p["name"]], p["unit"], data_type=p["data_type"], timezone=self.tz)

        # points not in the root resource
        self.add_timeseries('/humidity', '%RH', data_type="double")

        
        for a in self.actuators:
            setup = {'ip': self.ip}
            setup["name"] = a["name"]
            if a["act_type"] == "discrete":
                setup["states"] = a["states"]
                act = DiscreteActuator(**setup)
                ts[a['name']].add_actuator(act)
            elif a["act_type"] == "continuous":
                setup["range"] = a["range"]
                act = ContinuousActuator(**setup)
                ts[a['name']].add_actuator(act)
            else:
                print 'invalid actuator type'
                continue

        # setup metadata for each timeseries
        metadata_type = [
                ('/temp','Sensor'),
                ('/humidity','Sensor'),
                ('/temp_heat','Reading'),
                ('/temp_heat_act','SP'),
                ('/temp_cool','Reading'),
                ('/temp_cool_act','SP'),
                ('/hold','Reading'),
                ('/hold_act','Command'),
                ('/override','Reading'),
                ('/override_act','Command'),
                ('/hvac_mode','Reading'),
                ('/hvac_mode_act','Command')
            ]
        for ts, tstype in metadata_type:
            self.set_metadata(ts,{'Metadata/Type':tstype})


    def start(self):
        # call self.read every self.rate seconds
        periodicSequentialCall(self.read).start(self.rate)

    def read(self):
        url = 'http://' + self.ip + "/tstat"
        r = requests.get(url)
        if not r.ok:
            return
        vals = json.loads(r.text)
         
        for p in self.points:
            if p['name'] not in vals: # sometimes the ct80 hiccups and doesn't give data
                return
            if type(vals[p['name']]) not in [int, float]:
                return
            self.add('/' + self.translate[p["name"]], vals[p["name"]])

        r = requests.get(url + '/humidity')
        val = json.loads(r.text)
        self.add('/humidity', val['humidity'])

class _CT80Actuator(actuate.SmapActuator):
    def __init__(self, **opts):
        self.ip = opts.get('ip', None)
        self.name = opts.get('name', None)
        self.url = 'http://' + self.ip + '/tstat'
        actuate.SmapActuator.__init__(self, opts.get('archiver'))
        self.subscribe(opts.get('subscribe'))

    def get_state(self, request):
        r = requests.get(self.url)
        rv = json.loads(r.text)
        return self.parse_state(rv.get(self.name,-1))
 
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

