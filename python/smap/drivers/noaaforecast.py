'''
sMAP driver for NOAA weather forecasts
@author: Andrew Krioukov
'''
import time
import re
import logging
from smap.driver import SmapDriver
from smap.util import periodicSequentialCall
from smap.contrib import dtutil
import dateutil.parser
import urllib, urllib2
import BeautifulSoup
import json

class NOAAElement():
  def __init__(self, tag_name, type_name, code_name, units):
    self.tag_name = tag_name
    self.type_name = type_name
    self.code_name = code_name
    self.units = units

class NOAAForecast(SmapDriver):
  # Map of forecast variable names to NOAA codes
  # http://graphical.weather.gov/xml/docs/elementInputNames.php
  element_map = {
    'temperature' : NOAAElement('temperature', 'hourly', 'temp', 'Fahrenheit'),
    'wind-speed' : NOAAElement('wind-speed', 'sustained', 'wspd', 'knots'),
    'wind-dir' : NOAAElement('direction', 'wind', 'wdir', 'degrees true'),
    'dew-point' : NOAAElement('temperature', 'dew point', 'dew', 'Fahrenheit'),
    'humidity' : NOAAElement('humidity', 'relative', 'rh', 'percent'),
    'cloud-cover' : NOAAElement('cloud-amount', 'total', 'sky', 'percent'),
    'rain' : NOAAElement('precipitation', 'liquid', 'qpf', 'inches'),
  }

  def setup(self, opts):
    args = {
      'lat': opts.get('lat'),
      'lon': opts.get('lon'),
      'product': 'time-series',
      'Unit': 'e',
    }
    elements = [x.strip() for x in opts.get('elements').split(',') if x.strip() in self.element_map]

    baseurl = 'http://graphical.weather.gov/xml/sample_products/browser_interface/ndfdXMLclient.php'
  
    self.set_metadata('/', {
      'Location/Uri' : baseurl,
      'Metadata/Location/Latitude' : args['lat'],
      'Metadata/Location/Longitude' : args['lon'],
      })

    for name in elements:
      e = self.element_map[name]
      args[e.code_name] = e.code_name
      self.add_timeseries('/' + name, e.units, data_type='double')

    self.url = baseurl + '?' + urllib.urlencode(args)

  def start(self):
    periodicSequentialCall(self.read).start(60*60)

  def read(self):
    for retry_time in [0, 30, 5*60]:
      time.sleep(retry_time)
      try:
        print "Reading"
        data = urllib2.urlopen(self.url, timeout = 30).read()
        times = {}

        b = BeautifulSoup.BeautifulSoup(data)
        
        # Parse time blocks
        data = b.find('data')
        for time_block in data.findAll('time-layout'):
          key = time_block.find('layout-key').contents[0]
          time_list = []
          for time_tag in time_block.findAll('start-valid-time'):
            #dt = datetime.datetime.strptime(time_str, '%Y-%m-%dT%H:%M:%S%z')
            dt = dateutil.parser.parse(time_tag.string)
            time_list.append(dtutil.dt2ts(dt))
          times[key] = time_list

        # For each value block find referenced time block and add readings
        for data_block in data.find('parameters').findAll(recursive=False):
          key = data_block['time-layout']
          # Find the element being returned
          for (name, e) in self.element_map.items():
            if e.tag_name == data_block.name and e.type_name == data_block['type']:
              # Element found
              value = []
              for v in data_block.findAll('value'):
                value.append(float(v.string))
              
              for t,v in zip(times[key], value):
                self.add('/'+name, int(t), v)
              break
        return
      except Exception, e:
        print e
      # Error occured retry
