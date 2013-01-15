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
Drivers for HTP devices
"""
import struct

from smap.drivers import modbus
from smap.drivers.modbus import ModbusRegister as R
from smap.iface.modbustcp.ModbusTCP import ModbusRTU, FUNC_READ_INPUT

t = modbus.FactorStruct('>h', 0.1)

class VersaFlame(modbus.ModbusDriver):
    # this guy used RTU
    CLIENT = ModbusRTU
    MAX_READ_RANGE = 5
    REGISTERS = {
        # input registers
        51 : R("/ntc6", "F", t, "NTC 6 Temperature", FUNC_READ_INPUT),
        52 : R("/ntc7", "F", t, "NTC 7 Temperature", FUNC_READ_INPUT),
        53 : R("/solar_panel_temp", "F", t, "", FUNC_READ_INPUT),
        54 : R("/solar_flow", "LPM", t, "", FUNC_READ_INPUT),
        55 : R("/solar_temp", "F", t, "", FUNC_READ_INPUT),

        # holding registers
        4 : R("/tank_setpoint", "F", t, "Tank set point"),
        5 : R("/tank_temperature", "F", t, "Tank temperature"),
        6 : R("/oat", "F", t, "Outside air temperature"),
        }
