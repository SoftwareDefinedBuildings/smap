import math
from smap import driver
from smap.util import periodicSequentialCall

class VirtualPowerMeter(driver.SmapDriver):
    def setup(self, opts):
        self.powerreading = float(opts.get('initialreading',5.5))
        self.rate = float(opts.get('rate','1'))
        self.add_timeseries('/demand','kWh', data_type='double')

        self.set_metadata('/', {'Metadata/Device': 'Power Meter',
                                'Metadata/Model': 'Virtual Power Meter'})

        self.t = 1

    def start(self):
        periodicSequentialCall(self.read).start(self.rate)

    def read(self):
        self.t += 1
        self.powerreading = self.powerreading + .05*math.sin(.001 * self.t)
        self.add('/demand',float("{0:.2f}".format(self.powerreading)))




