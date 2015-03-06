from smap import driver, actuate
from smap.util import periodicSequentialCall

import threading
import importlib

class VirtualLight(driver.SmapDriver):
    def setup(self, opts):
        self.state = {'on': 0,
                      'bri': 100,
                      'hue': 5000,
                      'sat': 80
                      }
        self.readperiod = float(opts.get('ReadPeriod',.5))
        on = self.add_timeseries('/on', 'On/Off', data_type='long')
        bri = self.add_timeseries('/bri', 'Brightness', data_type='long')
        hue = self.add_timeseries('/hue', 'Hue', data_type='long')
        sat = self.add_timeseries('/sat', 'Saturation', data_type='long')

        self.set_metadata('/', {'Metadata/Device': 'Lighting Controller',
                                'Metadata/Model': 'Virtual Light',
                                'Metadata/Driver': __name__})

        archiver = opts.get('archiver')
        on.add_actuator(OnOffActuator(light=self, archiver=archiver, subscribe=opts.get('on')))
        bri.add_actuator(BrightnessActuator(light=self, range=(0,100), archiver=archiver, subscribe=opts.get('bri')))
        hue.add_actuator(HueActuator(light=self,range=(0,65535), archiver=archiver, subscribe=opts.get('hue')))
        sat.add_actuator(SatActuator(light=self,range=(0,100), archiver=archiver, subscribe=opts.get('sat')))

        metadata_type = [
                ('/on','Reading'),
                ('/on_act','Command'),
                ('/bri','Reading'),
                ('/bri_act','Command'),
                ('/hue','Reading'),
                ('/hue_act','Command'),
                ('/sat','Reading'),
                ('/sat_act','Command'),
                ]
        for ts, tstype in metadata_type:
            self.set_metadata(ts,{'Metadata/Type':tstype})

        if 'gui' in opts:
            guiobj = importlib.import_module(opts.get('gui'))
            self.gui = threading.Thread(target=guiobj.run)
            self.gui.daemon = True

    def start(self):
        periodicSequentialCall(self.read).start(self.readperiod)
        if hasattr(self, 'gui'):
            self.gui.start()

    def read(self):
        for k,v in self.state.iteritems():
            self.add('/'+k, v)

class VirtualLightActuator(actuate.SmapActuator):
    def __init__(self, **opts):
        self.light = opts.get('light')
        actuate.SmapActuator.__init__(self, opts.get('archiver'))
        self.subscribe(opts.get('subscribe'))


class OnOffActuator(VirtualLightActuator, actuate.BinaryActuator):
    def __init__(self, **opts):
        actuate.BinaryActuator.__init__(self)
        VirtualLightActuator.__init__(self, **opts)

    def get_state(self, request):
        return self.light.state.get('on')

    def set_state(self, request, state):
        self.light.state['on'] = int(state)
        return self.light.state.get('on')

class BrightnessActuator(VirtualLightActuator, actuate.ContinuousActuator):
    def __init__(self, **opts):
        actuate.ContinuousActuator.__init__(self, opts['range'])
        VirtualLightActuator.__init__(self, **opts)

    def get_state(self, request):
        return self.light.state.get('bri')

    def set_state(self, request, state):
        self.light.state['bri'] = int(state)
        return self.light.state.get('bri')

class HueActuator(VirtualLightActuator, actuate.ContinuousActuator):
    def __init__(self, **opts):
        actuate.ContinuousActuator.__init__(self, opts['range'])
        VirtualLightActuator.__init__(self, **opts)

    def get_state(self, request):
        return self.light.state.get('hue')

    def set_state(self, request, state):
        self.light.state['hue'] = int(state)
        return self.light.state.get('hue')

class SatActuator(VirtualLightActuator, actuate.ContinuousActuator):
    def __init__(self, **opts):
        actuate.ContinuousActuator.__init__(self, opts['range'])
        VirtualLightActuator.__init__(self, **opts)

    def get_state(self, request):
        return self.light.state.get('sat')

    def set_state(self, request, state):
        self.light.state['sat'] = int(state)
        return self.light.state.get('sat')
