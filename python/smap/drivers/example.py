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
from smap.driver import SmapDriver
from smap.util import periodicSequentialCall
from smap.contrib import dtutil

from twisted.internet import threads

class Driver(SmapDriver):
    def setup(self, opts):
        self.add_timeseries('/sensor0', 'V')
        self.set_metadata('/sensor0', {
            'Instrument/ModelName' : 'ExampleInstrument'
            })
        self.counter = int(opts.get('StartVal', 0))
        self.rate = float(opts.get('Rate', 1))

    def start(self):
        # Call read every 2 seconds
        periodicSequentialCall(self.read).start(self.rate)

    def read(self):
        self.add('/sensor0', self.counter)
        self.counter += 1

    def load(self, st, et, cache=None):
        d = threads.deferToThread(self.load_data, st, et)
        return d
 
    def load_data(self, st, et):
        st_utc = dtutil.dt2ts(st)
        et_utc = dtutil.dt2ts(et)
        ts = int(st_utc / 120) * 120 # round down to nearest 2-min increment
        while ts <= et_utc:
            self.add('/sensor0', ts, self.counter)
            self.counter += 1
            ts += 120 # 2-min increments
