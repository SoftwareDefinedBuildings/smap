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
@author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
"""
"""Classes for supporting performing actuation with sMAP.

sMAP services with actuation components should place actuators at the
leaves of their resource tree, replacing SmapPoint instances.
Generally, the steps necessary to provide actuation is simply to
subclass the appropriate actuator class (Binary, NState, or
Continuous), and then implement the get_state and set_state methods.

Services wishing to use access control should additionally use SSL for
authentication, and annotate their get and set methods with the
appropriate capabilities necessary to access those resources.
"""
import time
import urlparse
import traceback

from twisted.internet import defer
from zope.interface import implements

from smap import util
from smap.interface import *


class SmapActuator(object):
    """Classes that implement actuators should subclass this class.
    
    Actuators should have at least two attributes:
      control_type: the sMAP control model
      control_description: the sMAP description of this particular models

    Actuators should also implement several methods:
      valid_state(self, state): boolean test if a particular state is valid for this actuator
      parse_state(self, state): string from HTTP request parsing the
          submitted state into the form the actuator accepts
      translate_state(self, state)
          
    Actuators should also implement get and set methods.  The request
          object is included so that actuators my inspect the client
          request if they wish to perform checks based on the request.
      get_state(self, request): read the current state of this actuator
      set_state(self, request, val): write the state of the actuator

    Generally speaking, implementors will choose one of the default
    sMAP actuator models, and simply implement get and set methods.
    """

    # override all of these 
    control_type = None
    control_description = {}

    def valid_state(self, state):
        raise NotImplementedError()

    def parse_state(self, state):
        raise NotImplementedError()

    def translate_state(self, state):
        return state

    def get_state(self, request):
        raise NotImplementedError()

    def set_state(self, request):
        raise NotImplementedError()

    def get_description(self):
        d = { 'Model': self.control_type }
        d.update(self.control_description)
        return d

class BinaryActuator(SmapActuator):
    """A BinaryActuator is a controller which has only two states,
generally "on" and "off".  It is essentially a simplified version of
an NStateActuator.

State here are static and can't be configured.
    """
    control_type = 'binary'
    control_description = {
        'States' : [['0', 'off'], ['1', 'on']]
        }

    def valid_state(self, state):
        return state == 0 or state == 1

    def parse_state(self, state):
        for s in self.control_description['States']:
            if state.strip().lower() in s:
                return int(s[0])
        return None


class NStateActuator(SmapActuator):
    """NStateActuators have a discrete number of states which they can be
in.  Although there may be restrictions on which state transisitions
are possible, this profile does not express any of them.
    """
    control_type = 'discrete'
    control_description = {
        'Values' : []
        }

    def __init__(self, states=[]):
        self.control_description = {
            "Values": states
            }

    def valid_state(self, state):
        # return state >= 0 and state < len(self.control_description['Values'])
        return state in self.control_description['Values']

    def parse_state(self, state):
        return int(state)

    def translate_state(self, state):
        try:
            return self.control_description['Values'].index(state)
        except:
            return None


class ContinuousActuator(SmapActuator):
    """A ContinuousActuator allows a set point to be adjusted within a
continuous interval.  Minimum and maximum values in the range must be
specified.
    """
    control_type = 'continuous'
    control_description = {
        "MinValue": None,
        "MaxValue": None,
        }
    def __init__(self, range=[0, 1]):
        self.control_description = {
            "MinValue": range[0],
            "MaxValue": range[1],
            }

    def valid_state(self, state):
        return state >= self.control_description['MinValue'] and \
            state <= self.control_description['MaxValue']

    def parse_state(self, state):
        return float(state)


class ContinuousIntegerActuator(SmapActuator):
    """A ContinuousIntegerActuator allows a set point to be adjusted within a
continuous integer interval.  Minimum and maximum values in the range must be
specified.
    """
    ACTUATE_MODEL = 'continuousInteger'
    def valid_state(self, state):
        return state >= self.control_description['States'][0] and \
            state <= self.control_description['States'][1]

    def parse_state(self, state):
        return int(state)

    def __init__(self, control_range=[0, 1]):
        self.control_type = 'continuousInteger'
        self.control_description = {
            'States' : control_range,
            }


class GuardBandActuator(SmapActuator):
    """A GuardBandActuator actually consists of two points -- "high" and
"low", which are adjusted in parallel.
    """
    def __init__(self, **kwargs):
        self.control_type = 'guardband'
        SmapActuator.__init__(self, **kwargs)


if __name__ == '__main__':
    import uuid
    import server
    import json
    import sys
    from twisted.python import log
    from authentication import authenticated
    log.startLogging(sys.stdout)
    inst = core.SmapInstance('f80d0504-f2c6-11e0-80e6-ebc97648cfa4')


    class MyActuator(BinaryActuator):
        def setup(self, opts):
            self.state = 0
            BinaryActuator.setup(self, opts)

        def get_state(self, request):
            print request
            print "getting"
            self.add(self.state)
            return self.state
        
        @authenticated(["__has_ssl__"])
        def set_state(self, request, state):
            print "Setting state to", request,state
            self.state = state
            return self.state

#     class MyOtherActuator(ContinuousActuator):
#         def get_state(self, request):
#             return self.state
#         def set_state(self, request, state):
#             print "Setting state to", state
#             self.state = state
    act = MyActuator(inst.uuid('/a1'), 'UoM')
    import actuate

    inst.add_timeseries('/a1', act)
    inst.add_timeseries('/t1', 'V')
    rl = RateLimiter(10)
    
    a2 = inst.add_actuator('/a2', 'UoM', MyActuator, 
                           read_limit=10,
                           write_limit=10,
                           setup={})
    server.run(inst, port=8080)
#     a = MyActuator()
#     b = MyOtherActuator(range=[0, 5])
#     SmapHttp.start_server({'a': a, 'b': b}, port=8000, handler=SmapHttp.SslSmapHandler)
