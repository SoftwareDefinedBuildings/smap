
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
