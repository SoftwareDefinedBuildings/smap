import os
import serial
import sys
import time

from smap.drivers.enocean.api import USB300

from smap import actuate, driver
from smap.authentication import authenticated
from smap.util import periodicSequentialCall

class _Actuator(actuate.SmapActuator):

    def __init__(self, opts):
        self.state = 0
        
        self.usb_stick_id = opts['usb_stick_id']
        self.fixture_id = opts['fixture_id']
        self.serial_port = opts['serial_port']
        self.baud_rate = opts['baud_rate']
        self.dim_limits = opts['dim_limits']

        # Get Upper and lower limits for the fixture dim range
        self.lower_dim_bound = int(self.dim_limits[0])
        self.upper_dim_bound = int(self.dim_limits[1])

        self.api = USB300(self.serial_port, self.usb_stick_id, self.baud_rate, self.fixture_id)

        actuate.SmapActuator.__init__(self, opts.get('archiver'))
        self.subscribe(opts.get('subscribe'))

    def get_state(self, request):
        return self.state

    def set_state(self, request, state):
       
        """
        For the Terralux fixtures, valid values for dim level are between 0-1023. I thought that it would be easier
        to set these upper and lower bounds in the .ini file, and then use the easier to understand 0 - 100 range
        to control the dim setting.
        """

        self.state = int(state)
        
        # Make sure that a valid value is used to set the state of the fixture
        if self.state > 100:
            self.state = 100
        if self.state < 0:
            self.state = 0

        # Scale the range of the fixture by the dim level (0 - 100)
        if self.state > 0:
            payload = int((self.upper_dim_bound - self.lower_dim_bound) * self.state / 100)

        # The learn command must be sent before every actuation with the terralux fixtures
        self.api.tx_terralux_learn()
        
        if self.state == 0:
            try:
                self.api.tx_terralux_off()
            except:
                pass
        else:
            self.api.tx_terralux_on()
            self.api.tx_terralux_set_level(payload)

        return self.state

class ContinuousIntegerActuator(_Actuator, actuate.ContinuousIntegerActuator):
    def __init__(self, **opts):
        actuate.ContinuousIntegerActuator.__init__(self, [0, 100])
        _Actuator.__init__(self, opts)

class TerraluxController(driver.SmapDriver):

    def setup(self, opts):
        setup = {
            'usb_stick_id': opts.pop('usb_stick_id', 'ffe14000'),
            'serial_port': opts.pop('serial_port', '/dev/ttyUSB0'),
            'baud_rate': opts.pop('baud_rate', '57600'),
            'dim_limits': opts.pop('dim_limits'),
            'archiver': opts.get('archiver'),
        }

        self.fixture_ids = opts.pop('fixture_list')
        for fixture in self.fixture_ids:
            setup['fixture_id'] = fixture
            setup['subscribe'] = '/light_{0}/dim'.format(fixture)
            ts = self.add_timeseries('/light_%s/dim' % fixture, 'Dim Level', data_type='long', write_limit=5)
            ts.add_actuator(ContinuousIntegerActuator(**setup))
            self.set_metadata('/light_%s/dim' % fixture, {'Metadata/Type': 'Reading', 'Metadata/System': 'Lighting'})
            self.set_metadata('/light_%s/dim_act' % fixture, {'Metadata/Type': 'Command', 'Metadata/System': 'Lighting'})

