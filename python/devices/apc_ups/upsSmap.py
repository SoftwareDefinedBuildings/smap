"""
Smap source for APC UPS. Provides battery capcity readings.
"""
import sys
import time
import re

import signal
signal.signal(signal.SIGINT, signal.SIG_DFL)

sys.path.append("../../lib")
import simplesmap

class UpsStats(simplesmap.DataSource):
  def __init__(self):
    self['sensor'] = {
      'batt_cap': simplesmap.Channel('electric',
        simplesmap.Formatting(unit = 'Percent', multiplier = None, divisor = 10),
        simplesmap.Parameter(interval = 1, time = 'second'))}

  def update(self, value):
    self['sensor']['batt_cap'].add(simplesmap.Reading(time.time(), value))
    simplesmap.DataSource.update(self)

def main():
  stat = UpsStats()
  simplesmap.Server(port = 8002, sense_points = {'ups': stat})
  
  while True:
    out = simplesmap.cmd_output("snmpwalk -c public -v1 -m ./powernet398.mib 192.168.0.151 upsHighPrecBatteryCapacity")
  
    #example output: PowerNet-MIB::upsHighPrecBatteryCapacity.0 = Gauge32: 1000
    m = re.match("^.*: (\d+)$", out)
    if m:
      stat.update(int(m.group(1))) 
  
    time.sleep(1)

if __name__ == "__main__":
  main()
