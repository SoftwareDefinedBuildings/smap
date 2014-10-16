import os
import serial
import sys
import time

from smap.drivers.enocean.api import USB300

from smap import actuate, driver
from smap.authentication import authenticated

class _Actuator(actuate.SmapActuator):

    def __init__(self, opts):
        self.state = 0
        self.usb_stick_id = opts['usb_stick_id']
        self.serial_port = opts['serial_port']
        self.baud_rate = opts['baud_rate']
        self.destination_id = opts['destination_id']
       
        self.api = USB300(self.serial_port, self.usb_stick_id, self.baud_rate, self.destination_id)

    def get_state(self, request):
        return self.state

    def set_state(self, request, state):
        self.state = int(state)
        self.add('/state', self.state)
        #turn the switch on or off
        if(int(state)==1):
            self.api.tx_eep_rockerAI()
        if(int(state)==0):
            self.api.tx_eep_rockerAO()
        return self.state

class BinaryActuator(_Actuator, actuate.BinaryActuator):
    def __init__(self, **opts):
        actuate.BinaryActuator.__init__(self)
        _Actuator.__init__(self, opts)

class EnoceanPlugController(driver.SmapDriver):

    """
    Plug load controller must be paired with the USB300 Transceiver before this driver will work.
    Pair the Plug Load Controller by placing it into learn mode (Both buttons depressed for two seconds),
    And then call the link_plug_load_controller method from the enoceanAPI
    """
    def setup(self, opts):
        
        setup={'usb_stick_id': opts.pop('usb_stick_id', 'ffe14001'),
               'serial_port': opts.pop('serial_port', '/dev/ttyUSB0'),
               'baud_rate': opts.pop('baud_rate', '57600'),
               'destination_id': opts.pop('destination_id')
        }

        state = self.add_timeseries('/state', 'On/Off', data_type='long')
        state.add_actuator(BinaryActuator(**setup))
        self.set_metadata('/state', {'Metadata/Type': 'Reading'})
        self.set_metadata('/state_act', {'Metadata/Type': 'Command'})
