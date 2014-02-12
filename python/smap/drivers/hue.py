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

class HUE(driver.SmapDriver):

  api = [ {"api": "on", "access": "rw", "data_type":"long", "unit": "Mode",
    "act_type": "binary", "states": [0,1]},
    {"api": "bri", "access": "rw", "data_type":"long", "unit": "Brightness",
      "act_type": "continuousInteger", "range": (0,255)},
    {"api": "hue", "access": "rw", "data_type":"long", "unit": "Mode",
      "act_type": "continuousInteger", "range": (0,65535)},
    {"api": "sat", "access": "rw", "data_type":"long", "unit": "Saturation",
      "act_type": "continuousInteger", "range": (0,255)}
    ]
  def searchNewLights(self, ip, user):
    r = requests.post("http://" + ip + "/api/" + user + "/lights")
    print r.text

  def getLights(self, ip, user):
    r = requests.get("http://" + ip + "/api/"+user+"/lights")
    val = json.loads(r.text)
    print "lights available"
    return val

  def setup(self, opts):
    self.tz = opts.get('Metadata/Timezone', None)
    self.rate = float(opts.get('Rate', 5))
    self.ip = opts.get('ip', None)
    self.user = opts.get('user', None)
    self.lights = []
    # We search for any new lights
    self.searchNewLights(self.ip, self.user)
    # Get a list of lights
    val = self.getLights(self.ip, self.user)
    for i in val:
      for j in val[i]:
        self.lights.append({"id": str(i),
          "name": str(val[i][j].replace(' ', '').lower())})
    for light in self.lights:
      for option in self.api:
        if option["access"] == "rw":
          self.add_timeseries('/'+light['name']+'/state/'+option["api"],
              option["unit"], data_type=option["data_type"], timezone=self.tz)

          setup={'model': option["act_type"], 'ip':self.ip,
              'range': option.get("range"), 'user': self.user, 'id': light["id"],
              'api': option["api"]}
          if  option["act_type"] == "binary":
            setup['states'] = option.get("states")
            act = BinaryActuator(**setup)
          if  option["act_type"] == "continuousInteger":
            act = ContinuousIntegerActuator(**setup)
          if  option["act_type"] == "discrete":
            act = DiscreteActuator(**setup)

          self.add_actuator('/'+light['name'] + '/state/' + option["api"] + '_act',
              option["unit"], act, data_type = option["data_type"],
              write_limit=1)
        else:
          self.add_timeseries('/'+light['name']+'/state/'+option["api"],
              option["unit"], data_type=option["data_type"], timezone=self.tz)
  def start(self):
    # call self.read every self.rate seconds
    periodicSequentialCall(self.read).start(self.rate)
  def read(self):
    for light in self.lights:
      r = requests.get("http://" + self.ip + "/api/" + self.user + "/lights/"+light["id"])
      val = json.loads(r.text)
      for option in self.api:
        self.add('/'+light['name']+'/state/'+option["api"],
            int(val["state"][option["api"]]))

class Actuator(actuate.SmapActuator):

  def __init__(self, **opts):
    self.ip = opts['ip']
    self.user = opts['user']
    self.id = opts['id']
    self.api = opts['api']

  def get_state(self, request):
    r = requests.get("http://" + self.ip + "/api/"+self.user+"/lights/"+ self.id)
    val = json.loads(r.text)
    return self.parse_state(str(int(val["state"][self.api])))

  def set_state(self, request, state):
    if self.api == "on":
      state = bool(state)
    payload = {self.api: state}
    r = requests.put("http://" + self.ip + "/api/"+self.user+"/lights/"+self.id+"/state",
        data=json.dumps(payload))
    return state

class BinaryActuator(Actuator, actuate.BinaryActuator):
    def __init__(self, **opts):
        actuate.BinaryActuator.__init__(self)
        Actuator.__init__(self, **opts)

class DiscreteActuator(Actuator, actuate.NStateActuator):
    def __init__(self, **opts):
        actuate.NStateActuator.__init__(self, opts["states"])
        Actuator.__init__(self, **opts)

class ContinuousIntegerActuator(Actuator, actuate.ContinuousIntegerActuator):
    def __init__(self, **opts):
        actuate.ContinuousIntegerActuator.__init__(self, opts["range"])
        Actuator.__init__(self, **opts)
