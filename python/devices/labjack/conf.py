"""
Module lets you set up polling the labjack.  There's not much error
checking on this file, so buyer beware.  Pretty much the optional key
is the 'calibrate' function, which you can use to apply a
channel-specific modification to your data before it's published.

Also note that the analog inputs appear to start at 0, and increment
by 2 for each channel, so Ain1 = register 2.  You can access most of
the inputs on the Labjack by figuring out which register it is by
looking in the Labjack/Modbus map: http://labjack.com/support/modbus
"""

import labjack
from SmapPoint import SmapPoint, Formatting, Parameter, Reading

PORT=8023

CONF = {
    'ips' : {
         'address' : '128.32.37.170',
         'rate' : 10,
         'actuators' : {
              'dac0' : {
                   'register' : 5000,
                   'type' : labjack.LabjackDAC
                },
              'dac1' : {
                   'register' : 5002,
                   'type' : labjack.LabjackDAC
                },
            },
         'channels' : {
             'dc_bus' : {
                   'register' : 2,
                   'formatting' : Formatting('V', multiplier=4, divisor=None,
                                             type='voltage', ctype='sensor'),
                   },
             'battery' : {
                   'register' : 0,
                   'formatting' : Formatting('V', multiplier=4, divisor=None,
                                             type='voltage', ctype='sensor'),
                   },
             'charge' : {
                   'register' : 4,
                   'formatting' : Formatting('A', multiplier=None, divisor=100,
                                             type='voltage', ctype='sensor'),
                   },
             'output' : {
                   'register' : 6,
                   'formatting' : Formatting('A', multiplier=None, divisor=100,
                                             type='voltage', ctype='sensor'),
                   },
             },
        },
    'fridge' : {
         'address' : '128.32.37.171',
         'rate' : 10,
         'channels' : {
              'NH4Cl' : {
                   'register' : 0,      # Ain0 
                   'formatting' : Formatting(unit="C", multiplier=None, divisor=None,
                                             type='temperature', ctype='sensor'),
                   'calibrate' : lambda x: - (x * 55.56 - 255.37 + 273.15),
                   },
              'freezer' : {
                   'register' : 2,      # Ain1
                   'formatting' : Formatting(unit="C", multiplier=None, divisor=None,
                                             type='temperature', ctype='sensor'),
                   'calibrate' : lambda x: (x * 100 - 273.15),
                   }
              }
         }
    }
    
