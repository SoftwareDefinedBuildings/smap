from smap import driver, actuate
from smap.util import periodicSequentialCall
from random import random

class VirtualController(driver.SmapDriver):
    def setup(self, opts):
        self.val = 0
        self.state = {'on': 0}
        self.readperiod = float(opts.get('ReadPeriod',.5))
        self.transition = float(opts.get('TransitionProb', 0.05))

        on = self.add_timeseries('/on', 'On/Off', data_type='long')

        self.set_metadata('/', {'Metadata/Device': 'General Controller',
                                'Metadata/Model': 'Virtual General Controller',
                                'Metadata/Driver': __name__})

        on.add_actuator(OnOffActuator(device=self))

        self.set_metadata('/on',{'Metadata/Type':'Reading'})
        self.set_metadata('/on_act',{'Metadata/Type':'Command'})

    def start(self):
        periodicSequentialCall(self.read).start(self.readperiod)

    def read(self):
        self.add('/on', self.state['on'])

class VirtualControllerActuator(actuate.SmapActuator):
    def __init__(self, **opts):
        self.device = opts.get('device')

class OnOffActuator(VirtualControllerActuator, actuate.BinaryActuator):
    def __init__(self, **opts):
        actuate.BinaryActuator.__init__(self)
        VirtualControllerActuator.__init__(self, **opts)

    def get_state(self, request):
        return self.device.state.get('on')

    def set_state(self, request, state):
        self.device.state['on'] = int(state)
        return self.device.state.get('on')
