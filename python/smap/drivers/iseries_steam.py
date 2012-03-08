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
import logging
import time
import socket

from twisted.python import log

import smap.driver as driver
import smap.util as util

class IseriesSteam(driver.SmapDriver):
    def setup(self, opts):
        self.host = opts.get("Host", "10.0.50.119")
        self.rate = int(opts.get("Rate", 30))
        self.add_timeseries("/0", "ga/min")
        self.add_timeseries("/1", "ga")
        self.set_metadata("/", {
            'Instrument/ModelName' : 'Moxa MB3170'
            })

    def start(self):
        self.last_add = 0
        self.accum = 0
        self.last_time = None
        util.periodicSequentialCall(self.update).start(1)

    def update(self, cmd="*01X01"):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(1)
            s.connect((self.host, 1000))
            s.send(cmd + "\r")
            s.flush()
            reply = s.recv(1024)
            s.close()
        except IOError, e:
            log.err()
            return None
        else:
            if reply.startswith(cmd[1:]):
                val = float(reply[len(cmd) - 1:-1])
                print val
                if val == None:
                   time.sleep(0.5)
                   log.err("Failed to update reading")
                   return
            else:
                return
        this_time = util.now()

        # accumulate readings
        if self.last_time:
            self.accum += (self.last_time[1] + val) * ((this_time - self.last_time[0]) / 60) * 0.5

        # and output a reading ever RATE seconds
        if this_time - self.last_add > self.rate:
            self.add('/0', this_time, val)
            self.add('/1', this_time, accum)
            self.last_add = this_time
        self.last_time = (this_time, val)
