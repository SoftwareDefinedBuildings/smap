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

import sys
import socket
import struct
import random

FUNC_READ = 3

class ModbusTCP:
    def __init__(self, host, port=502, slaveaddr=1, timeout=2.0):
        self.remote = (host, port)
        self.slaveaddr = slaveaddr
        self.timeout = timeout

    def read(self, base, n):
        txid = random.randint(0, 65535)
        command = struct.pack(">HHHBBHH", txid, 0, 6, self.slaveaddr, FUNC_READ, base, n)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        sock.settimeout(self.timeout)
        
        sock.connect(self.remote)
        sock.send(command)
        data = sock.recv(1024)
        sock.close()

        txid_r, ver, length, addr, func = struct.unpack(">HHHBB", data[:8])
        # check for malformed replys
        if txid != txid_r or ver != 0 or addr != self.slaveaddr \
               or func != FUNC_READ or length != len(data) - 6:
            return None

        # print txid_r,ver,length,addr,func

        # just return the string -- the user knows how to unpack it
        # better then we probably do...
        return data[9:]

if __name__ == '__main__':
    reg = int(sys.argv[1])
    m = ModbusTCP('10.0.50.118')
    x = m.read(reg, 0)
    print [ord(c) for c in x]
