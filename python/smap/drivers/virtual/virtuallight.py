"""
These are sample drivers that make use of the virtual devices
"""
from smap.driver import SmapDriver
from smap import actuate
from smap.util import periodicSequentialCall
from smap.contrib import dtutil

from twisted.internet import threads
from twisted.python import log
import logging

from virtualdevices import VirtualLight, VirtualDimmableLight

class VirtualLightDriver(SmapDriver):
    def setup(self, opts):
        self.init_bosswave(opts.get('bosswave_key'))
        self.light = VirtualLight(0)
        self.add_timeseries('/state', 'On/Off')
        self.add_actuator('/state_act', 'On/Off', VirtualLightActuator(light=self.light))
        self.rate = .1

    def start(self):
        periodicSequentialCall(self.read).start(self.rate)

    def read(self):
        self.add('/state',self.light.get_state())

class VirtualLightActuator(actuate.BinaryActuator):
    def __init__(self, **opts):
        actuate.BinaryActuator.__init__(self)
        self.light = opts.get('light')

    def get_state(self, request):
        return self.light.get_state()

    def set_state(self, request, state):
        if int(state) == 1:
            self.light.on()
        else:
            self.light.off()
        return self.light.get_state()

class VirtualDimmableLightDriver(SmapDriver):
    def setup(self, opts):
        self.init_bosswave(opts.get('bosswave_key'))
        self.light = VirtualDimmableLight(0)
        self.add_timeseries('/state', 'Dimmable')
        self.add_actuator('/state_act', 'Dimmable', VirtualDimmableLightActuator(light=self.light,range=[0,100]))
        self.rate = 1

    def start(self):
        periodicSequentialCall(self.read).start(self.rate)

    def read(self):
        self.add('/state',self.light.get_state())

class VirtualDimmableLightActuator(actuate.ContinuousIntegerActuator):
    def __init__(self, **opts):
        actuate.ContinuousIntegerActuator.__init__(self,opts.get('range'))
        self.light = opts.get('light')

    def get_state(self, request):
        return self.light.get_state()

    def set_state(self, request, state):
        if state >=0 and state <= 100:
            self.light.set_state(state)
        return self.light.get_state()
