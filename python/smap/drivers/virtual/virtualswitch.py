from smap.driver import SmapDriver
from smap import actuate
from smap.util import periodicSequentialCall
from smap.contrib import dtutil

from twisted.internet import threads
from twisted.python import log
import logging

from virtualdevices import VirtualSwitch

class VirtualSwitchDriver(SmapDriver):
    def setup(self, opts):
        self.init_bosswave(opts.get('bosswave_key'))
        self.switch = VirtualSwitch(0)
        self.add_timeseries('/state', 'On/Off')
        self.add_actuator('/state_act', 'On/Off', VirtualSwitchActuator(switch=self.switch))
        self.rate = 1

    def start(self):
        periodicSequentialCall(self.read).start(self.rate)

    def read(self):
        self.add('/state', self.switch.get_state())

class VirtualSwitchActuator(actuate.BinaryActuator):
    def __init__(self, **opts):
        actuate.BinaryActuator.__init__(self)
        self.switch = opts.get('switch')
        self.switch.on()

    def get_state(self, request):
        return self.switch.get_state()

    def set_state(self, request, state):
        if int(state) == 1:
            self.switch.on()
        else:
            self.switch.off()
        return self.switch.get_state()

