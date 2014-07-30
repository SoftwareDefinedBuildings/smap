from smap import driver, actuate
from smap.util import periodicSequentialCall

class VirtualLight(driver.SmapDriver):
    def setup(self, opts):
        self.state = {'on': 0,
                      'bri': 100,
                      'hue': 5000,
                      'sat': 80
                      }
        self.readperiod = float(opts.get('ReadPeriod',.5))
        self.add_timeseries('/on', 'On/Off', data_type='long') 
        self.add_timeseries('/bri', 'Brightness', data_type='long') 
        self.add_timeseries('/hue', 'Hue', data_type='long') 
        self.add_timeseries('/sat', 'Saturation', data_type='long') 

        self.add_actuator('/on_act', 'On/Off', OnOffActuator(light=self))
        self.add_actuator('/bri_act', 'Brightness', BrightnessActuator(light=self,range=(0,100)))
        self.add_actuator('/hue_act', 'Hue', HueActuator(light=self,range=(0,65535)))

    def start(self):
        periodicSequentialCall(self.read).start(self.readperiod)

    def read(self):
        for k,v in self.state.iteritems():
            self.add('/'+k, v)

class VirtualLightActuator(actuate.SmapActuator):
    def __init__(self, **opts):
        self.light = opts.get('light')

    
class OnOffActuator(VirtualLightActuator, actuate.BinaryActuator):
    def __init__(self, **opts):
        actuate.BinaryActuator.__init__(self)
        VirtualLightActuator.__init__(self, **opts)

    def get_state(self, request):
        return self.light.state.get('on')
    
    def set_state(self, request, state):
        self.light.state['on'] = int(state)
        self.add(state)
        return self.light.state.get('on')

class BrightnessActuator(VirtualLightActuator, actuate.ContinuousActuator):
    def __init__(self, **opts):
        actuate.ContinuousActuator.__init__(self, opts['range'])
        VirtualLightActuator.__init__(self, **opts)

    def get_state(self, request):
        return self.light.state.get('bri')

    def set_state(self, request, state):
        self.light.state['bri'] = int(state)
        self.add(state)
        return self.light.state.get('bri')

class HueActuator(VirtualLightActuator, actuate.ContinuousActuator):
    def __init__(self, **opts):
        actuate.ContinuousActuator.__init__(self, opts['range'])
        VirtualLightActuator.__init__(self, **opts)

    def get_state(self, request):
        return self.light.state.get('hue')

    def set_state(self, request, state):
        self.light.state['hue'] = int(state)
        self.add(state)
        return self.light.state.get('hue')
