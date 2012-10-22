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
"""Driver for receiving statistics from a readingdb server
"""

import json

from twisted.internet.protocol import DatagramProtocol
from tx.ipv6.internet import reactor

from smap import driver

class Driver(driver.SmapDriver, DatagramProtocol):
    """Listen for statistics on whatever port from the readingdb
server; readingdb sends statistics on the IPv6/UDP port that clients
connect on.  They are sent as a json dict; this driver parses the json
and adds them as as a sMAP data source.
    """
    stats = ['adds', 'connects', 'disconnects', 
             'failed_add', 'nearest', 'queries']

    def setup(self, opts):
        for s in self.stats:
            self.add_timeseries('/' + s, 'count')
        self.port = int(opts.get('Port', 4242))

    def start(self):
        reactor.listenUDP6(self.port, self)

    def datagramReceived(self, data, addr):
        data = json.loads(data)
        for stat, v in data.iteritems():
            if not stat in self.stats: continue
            self._add('/' + stat, data['timestamp'], v)
