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

import os, requests, __builtin__
from smap import actuate, driver
from smap.authentication import authenticated
from smap.util import periodicSequentialCall
from smap.contrib import dtutil
from requests.auth import HTTPDigestAuth
import json
import time

from twisted.internet import threads

class _Actuator(actuate.SmapActuator):
    """Example Acutator which implements actuation by writing
    to an object
    """
    def __init__(self):
        self.state = 0
    def get_state(self, request):
        return self.state

    def set_state(self, request, state):
        self.state = state
        return state

class BinaryActuator(_Actuator, actuate.BinaryActuator):
    def __init__(self, range=None):
        _Actuator.__init__(self)
        actuate.BinaryActuator.__init__(self)

class ContinuousActuator(_Actuator, actuate.ContinuousActuator):
    def __init__(self, range=None):
        _Actuator.__init__(self)
        actuate.ContinuousActuator.__init__(self, range)

class DiscreteActuator(_Actuator, actuate.NStateActuator):
    def __init__(self, states=None):
        _Actuator.__init__(self)
        actuate.NStateActuator.__init__(self, states)

class VirtualThermostatDriver(driver.SmapDriver):
    """Driver that models a simple thermostat, state changes are written to files"""
    def setup(self, opts):
        self.tz = opts.get('Metadata/Timezone', None)
        self.rate = float(opts.get('Rate', 1))        
        devicename = opts.pop('Devicename', None)
        self.sensors = [ {"name": "heat_state", "unit": "State", "data_type": "long", "sources": ["temp_set_heat", "temp_set_cool", "temperature"], "devicename": devicename},
                {"name": "cool_state", "unit": "State", "data_type": "long", "sources": ["temp_set_heat", "temp_set_cool", "temperature"], "devicename": devicename},
                {"name": "on", "unit": "State", "data_type": "long", "sources": ["cool_state", "heat_state"], "devicename": devicename}]
        self.actuators = [  {"name": "temp_set_heat", "unit": "C", "data_type": "double", "range": (-100,100),"act_type": "continuous"},
                            {"name": "temp_set_cool", "unit": "C", "data_type": "double", "range": (-100,100),"act_type": "continuous"},
                            {"name": "temperature", "unit": "C", "data_type": "double", "range": (-100,100), "act_type": "continuous"},
                            {"name": "power", "unit": "W", "data_type": "double", "range": (0,10000),"act_type": "continuous"},
                            {"name": "heat", "unit": "W", "data_type": "double", "range": (-10000,10000),"act_type": "continuous"}
                            ]
        # set up an appropriate actuator
        for p in self.actuators:
            if p["act_type"] == "continuous":
                act = ContinuousActuator(range=map(float, (p["range"])))
            elif p["act_type"] == "binary":
                act = BinaryActuator()
            elif p["act_type"] == "discrete":
                act = DiscreteActuator(states=p["states"])
            else:
                raise ValueError("Invalid actuator model: " + opts['model'])
            self.add_actuator('/'+p["name"], p["unit"], act, data_type=p["data_type"], write_limit=0)

        for p in self.sensors:
            self.add_timeseries('/' + p["name"], p["unit"], data_type=p["data_type"], timezone=self.tz)

    def start(self):
        periodicSequentialCall(self.read).start(self.rate)

    def read(self):
        hysteresis = 1
        state = 0
        for p in self.sensors:
            for source in p["sources"]:
                url = 'http://localhost:8080/data/'+p["devicename"]+'/'+source
                r = requests.get(url)
                val = json.loads(r.text)
                result = val['Readings'][0][1]
                if source == "temperature":
                    temp = result
                elif source == "temp_set_heat":
                    heat_set = result
                elif source == "temp_set_cool":
                    cool_set = result
                elif source == "heat_state":
                    heat_state = result
                elif source == "cool_state":
                    cool_state = result
            if (temp != None and heat_set != None and cool_set != None):
                temp = float(temp)
                heat_set = float(heat_set)
                cool_set = float(cool_set)
                if p["name"] == "heat_state":
                    if temp > heat_set:
                        state = 0
                    elif temp < (heat_set-hysteresis):
                        state = 1
                elif p["name"] == "cool_state":
                    if temp > cool_set+hysteresis:
                        state = 1
                    elif temp < cool_set:
                        state = 0
                self.add('/' + p['name'], state)
                temp = None
                heat_set = None
                cool_set = None
            elif (heat_state != None and cool_state != None):
                heat_state = float(heat_state)
                cool_state = float(cool_state)
                if (heat_state == 0 and cool_state == 0):
                    state = 0
                else:
                    state = 1
                self.add('/' + p['name'], state)
                heat_state= None
                cool_state = None
