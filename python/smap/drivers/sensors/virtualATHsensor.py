import math
from smap import driver
from smap.util import periodicSequentialCall

class VirtualATHSensor(driver.SmapDriver):
    def setup(self, opts):
        self.tempreading = float(opts.get('initialtemp',70))
        self.humidityreading = float(opts.get('initialhumidity',40))
        self.rate = float(opts.get('rate','1'))
        self.add_timeseries('/temp','F', data_type='double')
        self.add_timeseries('/humidity','%RH', data_type='double')

        self.t = 1

    def start(self):
        periodicSequentialCall(self.read).start(self.rate)

    def read(self):
        self.t += 1
        self.tempreading += .05 * math.cos(.001 * self.t)
        self.humidityreading += .05 * math.cos(.001 * self.t)
        self.add('/temp',float("{0:.2f}".format(self.tempreading)))
        self.add('/humidity',float("{0:.2f}".format(self.humidityreading)))




