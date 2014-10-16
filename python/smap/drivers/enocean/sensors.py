import os
import serial
import sys
import time

from smap.drivers.enocean.api import USB300

from smap import driver
from smap.authentication import authenticated
from smap.util import periodicSequentialCall
from twisted.internet.task import LoopingCall

class EnoceanSensors(driver.SmapDriver):
    def setup(self, opts):
        
        # Retreive config information    
        self.usb_stick_id = opts.pop('usb_stick_id')
        self.plug_load_controller_list = opts.pop('plug_load_controller_list')
        self.fixture_ids = opts.pop('fixture_list')
        self.serial_port = opts.pop('serial_port')
        self.baud_rate = opts.pop('baud_rate')
        self.rate = opts.pop('rate')

        self.plug_load_controller_ids = self.plug_load_controller_list.split(',')

        for plug_load_controller in self.plug_load_controller_ids:
            self.add_timeseries('/plug_%s_sensor/status' % plug_load_controller, '', data_type="long")

        for fixture in self.fixture_ids:
            self.add_timeseries('/fixture_%s_sensor/mA' % fixture, 'mA', data_type="long")

        self.api = USB300(self.serial_port,self.usb_stick_id,self.baud_rate, 'ffffffff')

    def get_serial_data(self):

        """
        Function to retrieve the current readings (measured in mA) from the Terralux fixtures.
        This function will read from the serial buffer associated with the USB300 until the buffer is empty.

        This function can also handle data sent from Enocean Plug Load controllers
        """

        while self.api.checkSerialBuffer():
            try:
                data = self.api.getSerialData()

                # Check to see if packet is from a plug load controller
                if data[10:18] in self.plug_load_controller_list:
                    
                    #plug load controller is off
                    if data[9] == '8':
                        self.current_state = 0
                   #plug load controller is on
                    else:
                        self.current_state = 1

                    self.add('/plug_%s_sensor/status' % str(data[10:18]), self.current_state)

                
                # Check to see if packed is from a Terralux fixture
                elif data[10:18] in self.fixture_ids:
                    measured_level = data[2:6]
                    self.add('/fixture_%s_sensor/mA' % data[10:18], int(measured_level, 16))
            except:
                pass

        

    def start(self):

        """
        get_serial_data will be called with the requency specified by rate in the .ini
        The get_serial_data will read all of the readings stored in the serial buffer, so we
        don't need to worry about potentially missing a reading as it comes in.
        """

        lc = LoopingCall(self.get_serial_data)
        lc.start(int(self.rate))
