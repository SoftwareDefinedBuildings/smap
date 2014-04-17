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

import os

from smap import actuate, driver
from smap.authentication import authenticated

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


class VirtualPowerDriver(driver.SmapDriver):
    def setup(self, opts):
        self.tz = opts.get('Metadata/Timezone', None)
        self.actuators = [{"name": "power", "unit": "W", "data_type": "double", "range": (0,100000), "act_type": "continuous"}]
        # set up an appropriate actuator
        for p in self.actuators:
            if p["act_type"] == "continuous":
                act = ContinuousActuator(range=map(float, (p["range"])))
            elif p["act_type"] == "binary":
                act = BinaryActuator()
            elif p["act_type"] == "discrete":
                act = DiscreteActuator(states=p["act_type"])
            else:
                raise ValueError("Invalid actuator model: " + opts['model'])
            self.add_actuator('/'+p["name"], p["unit"], act, data_type=p["data_type"], write_limit=0)
