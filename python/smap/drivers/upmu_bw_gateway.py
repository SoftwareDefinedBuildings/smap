"""
BossWave to sMAP gateway driver

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
"""
@author Michael Andersen <m.andersen@cs.berkeley.edu>
"""
from smap.driver import SmapDriver
from twisted.internet import threads
from bosswave import BossWave
import datetime

class Driver(SmapDriver):
    bosswave_scheme = "bosswave://"
    def setup(self, opts):
        self.key = opts.get("bosswave-key", None)
        self.basetopic = opts.get("basetopic", None)
        
        if self.key is None:
            raise Exception("This driver requires a key")
        if self.basetopic is None:
            raise Exception("This driver requires a basetopic")
                
        for k in opts:
            if k.startswith(Driver.bosswave_scheme):
                t = k[len(Driver.bosswave_scheme):]
                mapto = opts[k].get(mapto,t)
                unit = opts[k].get("unit", "U")
                timeunit = opts[k].get("timeunit","ns")
                self.topics[t] = mapto
                
                self.add_timeseries("lock","bool",timeunit="ns")

                self.add_timeseries("L1/voltage/magnitude","V RMS", timeunit="ns")
                self.add_timeseries("L1/voltage/phase","DEG", timeunit="ns")
                self.add_timeseries("L2/voltage/magnitude","V RMS", timeunit="ns")
                self.add_timeseries("L2/voltage/phase","DEG", timeunit="ns")
                self.add_timeseries("L3/voltage/magnitude","V RMS", timeunit="ns")
                self.add_timeseries("L3/voltage/phase","DEG", timeunit="ns")
                
                self.add_timeseries("L1/current/magnitude","A RMS", timeunit="ns")
                self.add_timeseries("L1/current/phase","DEG", timeunit="ns")
                self.add_timeseries("L2/current/magnitude","A RMS", timeunit="ns")
                self.add_timeseries("L2/current/phase","DEG", timeunit="ns")
                self.add_timeseries("L3/current/magnitude","A RMS", timeunit="ns")
                self.add_timeseries("L3/current/phase","DEG", timeunit="ns")
                
    def _procmsg(self, p):
        el = ord(p[0]) + (ord(p[1])<<8) #Number of elements
        p = p[2:]
        for i in range(el):
            linenum = ord(p[0]) + (ord(p[1])<<8)
            datestr = p[2:32]
            
            while datestr[-1] == "\x00": datestr = datestr[:-1] 
            realdate = datetime.datetime.strptime(datestr[:-1], "%Y/%m/%d %H:%M:%S.%f")
            lock = ord(p[32]) == 1
            cols = []
            p = p[33:]
            for kk in range(12):
                cols += [(ord(p[0]) + (ord(p[1])<<8)) + (ord(p[2]) + (ord(p[3])<<8))/10000.0] 
                p = p[4:]
            if ((realdate - fromdate).total_seconds() >= 0 and
               (todate - realdate).total_seconds() >= 0):
                
                tns = (realdate - datetime.datetime.utcfromtimestamp(0)).total_seconds()*10000000
                tns = int(tns)*1000
                
                self.add("lock",timeunit="ns")
                
                self.add("L1/voltage/magnitude", tns, cols[0])
                self.add("L1/voltage/phase", tns, cols[1])
                self.add("L2/voltage/magnitude", tns, cols[2])
                self.add("L2/voltage/phase", tns, cols[3])
                self.add("L3/voltage/magnitude", tns, cols[4])
                self.add("L3/voltage/phase", tns, cols[5])
                
                self.add("L1/current/magnitude", tns, cols[6])
                self.add("L1/current/phase", tns, cols[7])
                self.add("L2/current/magnitude", tns, cols[8])
                self.add("L2/current/phase", tns, cols[9])
                self.add("L3/current/magnitude", tns, cols[10])
                self.add("L3/current/phase", tns, cols[11])
                
    def bw_event_handler(self, message, details):
        print "Got BW message :-)"
        self._procmsg(message)
    
    def start(self):
        self.bw = BossWave(key=self.key, root="/upmu/bin/")
        self.bw.init()
        self.root = self.bw.root()
        
        self.bw_event_handler = self.root.methodevent(self.basetopic)(self.bw_event_handler)
        self.root.init(self)
                #yield {"line":linenum, "realdate":realdate, "date":datestr,"lock":lock,"cols":cols}  
                
                          
       # self.add_timeseries('/sensor0', 'V', timeunit="s")
      #  self.set_metadata('/sensor0', {
      #      'Instrument/ModelName' : 'ExampleInstrument'
      #      })
      #  self.counter = int(opts.get('StartVal', 0))
      #  self.rate = float(opts.get('Rate', 1))

   # def start(self):
   #     bw.init()
        # Call read every 2 seconds
        # periodicSequentialCall(self.read).start(self.rate)

   # def read(self):
   #     self.add('/sensor0', self.counter)
   #     self.counter += 1

   # def load(self, st, et, cache=None):
   #     d = threads.deferToThread(self.load_data, st, et)
   #     return d
 
   # def load_data(self, st, et):
   #     st_utc = dtutil.dt2ts(st)
   #     et_utc = dtutil.dt2ts(et)
   #     ts = int(st_utc / 120) * 120 # round down to nearest 2-min increment
   #     while ts <= et_utc:
   #         self.add('/sensor0', ts, self.counter)
   #         self.counter += 1
   #         ts += 120 # 2-min increments
            
