import math
from smap import driver
from smap.util import periodicSequentialCall

class VirtualLightSensor(driver.SmapDriver):
    def setup(self, opts):
        self.luxreading = float(opts.get('initiallux',40))
        self.rate = float(opts.get('rate','1'))
        self.add_timeseries('/illumination','Lx', data_type='double')
        self.set_metadata('/illumination',{'Metadata/Sensor': 'Illumination'})

        self.set_metadata('/', {'Metadata/Device': 'Illumination Sensor',
                                'Metadata/Model': 'Virtual Light Sensor',
                                'Metadata/Driver': __name__})

        self.t = 1

    def start(self):
        periodicSequentialCall(self.read).start(self.rate)

    def read(self):
        self.t += 1
        self.luxreading += .05 * math.cos(.001 * self.t)
        self.add('/illumination',float("{0:.2f}".format(self.luxreading)))




