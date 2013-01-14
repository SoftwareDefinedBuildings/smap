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

import collections
import struct

from twisted.python import log

from smap.driver import SmapDriver
from smap.util import periodicSequentialCall
from smap.iface.modbustcp.ModbusTCP import ModbusTCP, ModbusError

float = struct.Struct(">f")

class ModbusDriver(SmapDriver):
    """Generic base class for drivers polling modbus devices"""

    # max number of registers to read in one go
    MAX_READ_RANGE = 100
    METADATA = {}
    REGISTERS = {}
    BASE = 0

    def setup(self, opts):
        self.host = opts.get('Address')
        self.port = int(opts.get('Port', 502))
        self.rate = int(opts.get('Rate', 30))
        self.slaveaddr = int(opts.get('SlaveAddress', 1))
        self.base = int(opts.get('BaseRegister', self.BASE))

        self.set_metadata('/', self.METADATA)
        self.set_metadata('/', {
                'Instrument/SamplingPeriod' : str(self.rate),
                })

        for desc, path, units, fmt in self.REGISTERS.itervalues():
            self.add_timeseries(path, units, 
                                data_type='double', description=desc)

    def start(self):
        self.m = ModbusTCP(self.host, self.port, self.slaveaddr)
        periodicSequentialCall(self.update).start(self.rate)

    def stop(self):
        self.m.close()

    def update(self):
        """Poll the Modbus/TCP device and interpret the response"""
                    
        for offset in xrange(0, max(self.REGISTERS.keys()), self.MAX_READ_RANGE):
            try:
                data = self.m.read(self.base + offset, self.MAX_READ_RANGE)
            except ModbusError:
                log.err("Modbus protocol error; restarting connection")
                self.m.close()
                self.m = ModbusTCP(self.host, self.port, self.slaveaddr)
                return
            except Exception, e:
                log.err("Exception polling PQube meter at (%s:%i): %s" % 
                        (self.host, self.port, str(e)))
                return
            else:
                if len(data) != self.MAX_READ_RANGE * 2:
                    log.err("Wrong data length from (%s:%i)" % (self.host, self.port))
                    return

            for i in xrange(0, self.MAX_READ_RANGE * 2, 4):
                if (offset+i) / 2 in self.REGISTERS:
                    desc, path, units, fmt = self.REGISTERS[(offset+i) / 2]
                    self.add(path, fmt.unpack(data[i:i+fmt.size])[0])
