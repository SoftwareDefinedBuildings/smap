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
@author Gabe Fierro <gt.fierro@berkeley.edu>
"""

from smap.driver import SmapDriver
from smap.util import periodicSequentialCall
from smap.contrib import dtutil
import requests
from requests.exceptions import ConnectionError
import json
from smap import actuate
import time

from twisted.internet import threads

class CT80(SmapDriver):
    """
    The CT80 has a quirk in its API in which writing to t_heat (temp_heat) will change the mode of the thermostat to HEAT
    as well as changing the heating setpoint. This has the effect of ignoring any cooling setpoint, and the thermostat will
    not switch modes if it needs to. This is also true for setting t_cool (temp_cool).

    We solve this by having an internal cache of the latest temp_heat and temp_cool setpoints as seen by POST requests to the
    sMAP driver. Everytime the `read` function is run, we compare the current temperature to our heating and cooling setpoints
    and use the CT80's API to set either t_heat or t_cool, depending on which setpoint the current temp reading is closest to
    """
    def setup(self, opts):
        self.tz = opts.get('Timezone', 'America/Los_Angeles')
        self.rate = float(opts.get('Rate', 5))
        self.archiver = opts.get('archiver','http://localhost:8079')
        self._temp_heat_subscription = opts.get('temp_heat','')
        self._temp_cool_subscription = opts.get('temp_cool','')
        self.ip = opts.get('ip', None)
        self._setpoints = {'t_heat': 60,
                           't_cool': 80}
        self._sp_actuators = {'temp_heat': None,
                              'temp_cool': None}

        # driver-specific metadata
        self.set_metadata('/', {'Metadata/Device': 'Thermostat',
                                'Metadata/Model': 'CT80 RTA',
                                'Metadata/Driver': __name__})
        # list of API points
        self.points = [
                        {"smapname": "temp", "name": "temp", "unit": "F", "data_type": "double"},
                        {"smapname": "hvac_mode", "name": "tmode", "unit": "Mode", "data_type": "double"},
                        {"smapname": "hvac_state", "name": "tstate", "unit": "State", "data_type": "double"},
                        {"smapname": "fan_mode", "name": "fmode", "unit": "Mode", "data_type": "double"},
                        {"smapname": "fan_state", "name": "fstate", "unit": "State", "data_type": "double"},
                        {"smapname": "override", "name": "override", "unit": "Mode", "data_type": "double"},
                        {"smapname": "hold", "name": "hold", "unit": "Mode", "data_type": "double"},
                        {"smapname": "temp_heat", "name": "t_heat", "unit": "F", "data_type": "double"},
                        {"smapname": "temp_cool", "name": "t_cool", "unit": "F", "data_type": "double"},
                        {"smapname": "program_mode", "name": "program_mode", "unit": "Mode", "data_type": "double"}
                      ]
        self.actuators = [
            {"smapname": "temp_heat", "name": "t_heat", "act_type": "continuous", "unit": "F", "data_type": "double", "range": (40,100), "subscribe": self._temp_heat_subscription},
            {"smapname": "temp_cool", "name": "t_cool", "act_type": "continuous", "unit": "F", "data_type": "double", "range": (40,100), "subscribe": self._temp_cool_subscription},
            {"smapname": "hvac_mode", "name": "tmode", "act_type": "discrete", "unit": "F", "data_type": "double", "states": [0,1,2,3], "subscribe":""},
            {"smapname": "fan_mode", "name": "fmode", "act_type": "binary", "unit": "F", "data_type": "double", "subscribe":""},
            {"smapname": "override", "name": "override", "act_type": "binary", "unit": "F", "data_type": "double", "subscribe":""},
            {"smapname": "hold", "name": "hold", "act_type": "binary", "unit": "F", "data_type": "double", "subscribe":""},
            {"smapname": "program_mode", "name": "program_mode", "act_type": "binary", "unit": "F", "data_type": "double", "subscribe":""},
          ]

        ts = {}
        # add timeseries
        for p in self.points:
            ts[p["smapname"]] = self.add_timeseries('/' + p["smapname"], p["unit"], data_type=p["data_type"], timezone=self.tz)

        # points not in the root resource
        self.add_timeseries('/humidity', '%RH', data_type="double")

        # set timeseries-specific metadata
        self.set_metadata('/temp', {'Metadata/Sensor': 'Temperature'})
        self.set_metadata('/humidity', {'Metadata/Sensor': 'Humidity'})

        # instantiate actuators
        for a in self.actuators:
            setup = {'ip': self.ip, 'driver': self, 'name': a['name']}
            if a['subscribe']:
                setup['subscribe'] = a['subscribe'] # skip empty subscriptions
            if a["act_type"] == "discrete":
                setup["states"] = a["states"]
                act = DiscreteActuator(**setup)
                ts[a['smapname']].add_actuator(act)
            elif a["act_type"] == "continuous":
                setup["range"] = a["range"]
                act = ContinuousActuator(**setup)
                if a['smapname'] in ['temp_heat', 'temp_cool']:
                    self._sp_actuators[a['smapname']] = act
                ts[a['smapname']].add_actuator(act)
            elif a["act_type"] == "binary":
                act = BinaryActuator(**setup)
                ts[a['smapname']].add_actuator(act)


    def start(self):
        # call self.read every self.rate seconds
        periodicSequentialCall(self.read).start(self.rate)

    def read(self):
        url = 'http://' + self.ip + "/tstat"
        try:
            r = requests.get(url)
        except ConnectionError as e:
            print 'error connecting',e
            return
        if not r.ok:
            print 'got status code',r.status_code,'from api'
            return
        vals = json.loads(r.text)

        if 't_heat' not in self.points and 't_cool' not in vals: # hiccup
            return

        for p in self.points:
            if p['name'] not in vals or p['name'] in ['t_heat','t_cool']: # sometimes the ct80 hiccups and doesn't give data OR the mode limits what we see
                continue
            if type(vals[p['name']]) not in [int, float]:
                return
            self.add('/' + p["smapname"], float(vals[p["name"]]))

        # check which setpoint to write: if current temp is closer to heating setpoing,
        # set t_heat, else set t_cool
        if self._setpoints['t_heat'] is not None and self._setpoints['t_cool'] is not None:
            self.add('/temp_heat', float(self._setpoints['t_heat']))
            self.add('/temp_cool', float(self._setpoints['t_cool']))
            if abs(self._setpoints['t_heat'] - vals['temp']) < abs(self._setpoints['t_cool'] - vals['temp']):
                print 'Writing temp_heat', self._setpoints['t_heat']
                self._sp_actuators['temp_heat'].set_state(None, self._setpoints['t_heat'])
            else:
                print 'Writing temp_cool', self._setpoints['t_cool']
                self._sp_actuators['temp_cool'].set_state(None, self._setpoints['t_cool'])
        else: # publish the current t_heat, t_cool of the thermostat
            if 't_heat' in vals:
                self.add('/temp_heat', float(vals['t_heat']))
            if 't_cool' in vals:
                self.add('/temp_cool', float(vals['t_cool']))

        r = requests.get(url + '/humidity')
        val = json.loads(r.text)
        self.add('/humidity', float(val['humidity']))

class _CT80Actuator(actuate.SmapActuator):
    def __init__(self, **opts):
        self.ip = opts.get('ip', None)
        self.name = opts.get('name', None)
        self.driver = opts.get('driver')
        self.url = 'http://' + self.ip + '/tstat'

    def get_state(self, request):
        r = requests.get(self.url)
        rv = json.loads(r.text)
        return self.parse_state(rv.get(self.name,-1))

    def set_state(self, request, state):
        # if we get a web request for temp_heat or temp_cool, we cache it but
        # don't actuate the CT80. To write temp_heat or temp_cool to the CT80,
        # we have to have request == None
        if request and self.name in ['t_heat','t_cool']:
            self.driver._setpoints[self.name] = state
            return
        payload = '{"' + self.name + '": ' + str(state) + '}'
        r = requests.post(self.url, data=payload)
        return state

class BinaryActuator(_CT80Actuator, actuate.BinaryActuator):
    def __init__(self, **opts):
        actuate.BinaryActuator.__init__(self)
        _CT80Actuator.__init__(self, **opts)

class DiscreteActuator(_CT80Actuator, actuate.NStateActuator):
    def __init__(self, **opts):
        actuate.NStateActuator.__init__(self, opts['states'])
        _CT80Actuator.__init__(self, **opts)

class ContinuousActuator(_CT80Actuator, actuate.ContinuousActuator):
    def __init__(self, **opts):
        actuate.ContinuousActuator.__init__(self, opts['range'])
        _CT80Actuator.__init__(self, **opts)
