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
from smap.driver import SmapDriver
from smap import actuate
from smap.util import periodicSequentialCall
from smap.contrib import dtutil

from twisted.internet import threads
from twisted.python import log
import logging

counter = 0

class Driver(SmapDriver):
    def setup(self, opts):
        self.init_bosswave(opts.get('bosswave_key'))
        #self.add_timeseries('/sensor0', 'V')
        #self.add_timeseries('/sensor1', 'V')
        self.add_timeseries('/sensor0', 'V', emitter_path='test/gabe')
        self.add_timeseries('/sensor1', 'V', emitter_path=['test/sensor1','test/gabe'])
        self.add_actuator('/sensor0_act', 'V', ContinuousIntegerActuator(range=(0,100)))
        self.set_metadata('/sensor0', {
            'Instrument/ModelName' : 'ExampleInstrument'
            })
        self.rate = float(opts.get('Rate', 1))

    def start(self):
        # Call read every 2 seconds
        periodicSequentialCall(self.read).start(self.rate)

    def read(self):
        global counter
        self.add('/sensor0', counter)
        self.add('/sensor1', counter*2)
        counter += 1

class ContinuousIntegerActuator(actuate.ContinuousIntegerActuator):
    def __init__(self, **opts):
        actuate.ContinuousIntegerActuator.__init__(self, opts['range'])

    def get_state(self, request):
        global counter
        return counter

    def set_state(self, request, state):
        global counter
        counter = int(state)
        return counter
