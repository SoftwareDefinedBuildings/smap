
import sys
import logging
import time
import threading
import urllib2

sys.path.append("../../newlib")
import util

import SmapHttp
import SmapInstance
import smaplog
from SmapPoint import SmapPoint, Reading, Parameter
from SmapActuate import BinaryActuator, ContinuousActuator
from SmapAuthorization import authenticated

from labjackpython import ue9

"""
sMAP interface for Labjack devices -- currently the UE9 series.

We use the LabjackPython module provided by labjack to talk to the
device over Ethernet.  This uses their Modbus interface, which means
you need to have comm firmware version >=1.5 installed.  You can grab
it from here: http://labjack.com/support/firmware/ue9/beta, and
install it using the windows tool or their Python updater.

The conf module lists what feeds are presented in sMAP.  See that
module for info on adding new channels, etc.

@author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
"""

class LabjackUpdater:
    def __init__(self, ljname, configuration, device, lock):
        self.ljname = ljname
        self.conf = configuration
        self.dev = device
        self.lock = lock
        self.timer = util.RateTimer(self.conf['rate'], lambda: self.update())

    def set_instance(self, inst):
        self.inst = inst

    def update(self):
        myplace = self.inst['data'][self.ljname]
        for name, point in self.conf['channels'].iteritems():
            with self.lock:
                v = self.dev.readRegister(point['register'])
            ts = time.time()
            print point['register'],
            if callable(point.get('calibrate', None)):
                print v,
                v = point['calibrate'](v)

            myplace[point['formatting'].ctype][name].add(Reading(time=ts,
                                                                 value=v,
                                                                 min=None,
                                                                 max=None))
            print v
        self.inst.push('~/data/' + self.ljname + '/sensor/')

    def start(self):
        self.timer.start()


class LabjackDIO(BinaryActuator):
    def __init__(self, device, register, lock):
        BinaryActuator.__init__(self, lock=lock)
        self.device = device
        self.register = register

    def get_state(self, request):
        """Get the device state.  Actually query the device each time so we
don't have any problems with state being out of date..."""
        return self.dev.readRegister(self.register)

    @authenticated(['CAP_AUTHENTICATED'])
    def set_state(self, request, state):
        if state == "1" or state == "on":
            state = 1
        elif state == "0" or state == "off":
            state = 0
        self.dev.writeRegister(self.register, state)


class LabjackDAC(ContinuousActuator):
    def __init__(self, device, register, lock):
        ContinuousActuator.__init__(self, range=[0.0,5.0], lock=lock, unit='V')
        self.dev = device
        self.register = register
        self.last = (0, None)
        
    def get_state(self, request):
        print self.last, abs(time.time() - self.last[0])
        if abs(time.time() - self.last[0]) > 0.5:
            self.last = (time.time(),
                         self.dev.readRegister(self.register))          
        return self.last[1]
    
    @authenticated(['CAP_AUTHENTICATED'])
    def set_state(self, request, state):
        self.dev.writeRegister(self.register, float(state))

if __name__ == '__main__':
    smaplog.start_log(screenLevel=logging.DEBUG)
    # import config
    if len(sys.argv) == 2:
        c = __import__(sys.argv[1])
    else:
        c = __import__('conf')

    # create the instance heirarchy from the configuration
    data = {}
    updaters = []
    for device, conf in c.CONF.iteritems():
        print conf['address']
        dev = ue9.UE9(ipAddress=conf['address'], ethernet=True)
        lock = threading.RLock()

        data[device] = {}
        for channel_name, channel_conf in conf['channels'].iteritems():
            typ = data[device].get(channel_conf['formatting'].ctype, {})
            typ[channel_name] = SmapPoint(channel_conf['formatting'],
                                          Parameter(interval=conf['rate'],
                                                    time='second'))
            data[device][channel_conf['formatting'].ctype] = typ

        for act_name, act_conf in conf.get('actuators', {}).iteritems():
            act = data[device].get('actuate', {})
            act[act_name] = act_conf['type'](dev, act_conf['register'], lock)
            data[device]['actuate'] = act
            
        updaters.append(LabjackUpdater(device, conf, dev, lock))

    inst = SmapInstance.SmapInstance(data, key="labjack")
    map(lambda x: x.set_instance(inst), updaters)
    map(lambda x: x.start(), updaters)
    SmapHttp.start_server(inst, port=c.PORT)
