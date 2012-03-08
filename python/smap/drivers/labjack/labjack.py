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

import socket
import time
from twisted.python import log
from smap import driver, core, util
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
"""
def build_calibrate(cconf):
    if 'calibrate' in cconf:
        return cconf['calibrate']
    mult, div = cconf.get('multiplier', None), cconf.get('divisor', None)
    if mult and div == None: return lambda x: x * mult
    elif div and mult == None: return lambda x: x / div
    elif mult == None and div == None: return lambda x: (x * mult) / div
    else: return lambda x: x

class ReconnectingUE9(ue9.UE9):
    def __init__(self, **kwargs):
        self.openargs = kwargs
        ue9.UE9.__init__(self, **kwargs)

    def readRegister(self, reg):
        try:
            return ue9.UE9.readRegister(self, reg)
        except socket.error:
            log.err("ue9 device socket error; reopening connection")
            self.close()
            time.sleep(3)
            self.open(**self.openargs)
            return ue9.UE9.readRegister(self, reg)

class LabjackDriver(driver.SmapDriver):
    def setup(self, opts):
        if not 'ConfModule' in opts:
            raise core.SmapException("The LabJack driver requires an "
                                     "additional configuration module")
        cmps = opts.get('ConfModule').split('.')
        mod = __import__('.'.join(cmps), globals(), locals(), ['CONF']) 
        self.labjacks = {}
        for ljname, ljconf in mod.CONF.iteritems():
            # create all the time series and calibration functions
            dev = ReconnectingUE9(ipAddress=ljconf['address'], ethernet=True)
            self.labjacks[ljname] = (ljconf, dev)

            for cname, cconf in ljconf['channels'].iteritems():
                cconf['calibrate'] = build_calibrate(cconf)
                path = '/%s/%s' % (ljname, cname)
                self.add_timeseries(path,
                                    cconf['unit'], 
                                    data_type='double')
                meta = { 'Extra/Register' : str(cconf['register']) }
                meta.update(cconf.get('metadata', {}))
                self.set_metadata(path, meta)

        self.set_metadata('/', {
                'Instrument/Manufacturer' : 'LabJack Corporation',
                'Instrument/Model' : 'UE9',
                'Extra/Driver' : 'smap.drivers.labjack.labjack.LabjackDriver'
                })

    def start(self):
        for ljname, (ljconf, dev) in self.labjacks.iteritems():
            util.periodicSequentialCall(self.update, ljname, dev, ljconf).start(ljconf['rate'])

    def update(self, ljname, dev, ljconf):
        for cname, cconf in ljconf['channels'].iteritems():
            v = dev.readRegister(cconf['register'])
            self.add('/%s/%s' % (ljname, cname), 
                     cconf['calibrate'](v))


# class LabjackDIO(BinaryActuator):
#     def __init__(self, device, register, lock):
#         BinaryActuator.__init__(self, lock=lock)
#         self.device = device
#         self.register = register

#     def get_state(self, request):
#         """Get the device state.  Actually query the device each time so we
# don't have any problems with state being out of date..."""
#         return self.dev.readRegister(self.register)

#     @authenticated(['CAP_AUTHENTICATED'])
#     def set_state(self, request, state):
#         if state == "1" or state == "on":
#             state = 1
#         elif state == "0" or state == "off":
#             state = 0
#         self.dev.writeRegister(self.register, state)


# class LabjackDAC(ContinuousActuator):
#     def __init__(self, device, register, lock):
#         ContinuousActuator.__init__(self, range=[0.0,5.0], lock=lock, unit='V')
#         self.dev = device
#         self.register = register
#         self.last = (0, None)
        
#     def get_state(self, request):
#         print self.last, abs(time.time() - self.last[0])
#         if abs(time.time() - self.last[0]) > 0.5:
#             self.last = (time.time(),
#                          self.dev.readRegister(self.register))          
#         return self.last[1]
    
#     @authenticated(['CAP_AUTHENTICATED'])
#     def set_state(self, request, state):
#         self.dev.writeRegister(self.register, float(state))

# if __name__ == '__main__':
#     smaplog.start_log(screenLevel=logging.DEBUG)
#     # import config
#     if len(sys.argv) == 2:
#         c = __import__(sys.argv[1])
#     else:
#         c = __import__('conf')

#     # create the instance heirarchy from the configuration
#     data = {}
#     updaters = []
#     for device, conf in c.CONF.iteritems():
#         print conf['address']
#         dev = ue9.UE9(ipAddress=conf['address'], ethernet=True)
#         lock = threading.RLock()

#         data[device] = {}
#         for channel_name, channel_conf in conf['channels'].iteritems():
#             typ = data[device].get(channel_conf['formatting'].ctype, {})
#             typ[channel_name] = SmapPoint(channel_conf['formatting'],
#                                           Parameter(interval=conf['rate'],
#                                                     time='second'))
#             data[device][channel_conf['formatting'].ctype] = typ

#         for act_name, act_conf in conf.get('actuators', {}).iteritems():
#             act = data[device].get('actuate', {})
#             act[act_name] = act_conf['type'](dev, act_conf['register'], lock)
#             data[device]['actuate'] = act
            
#         updaters.append(LabjackUpdater(device, conf, dev, lock))

#     inst = SmapInstance.SmapInstance(data, key="labjack")
#     map(lambda x: x.set_instance(inst), updaters)
#     map(lambda x: x.start(), updaters)
#     SmapHttp.start_server(inst, port=c.PORT)
