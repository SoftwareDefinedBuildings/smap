#!/usr/bin/env python
'''
sMAP feed for CA ISO energy market data. Provides price feeds for three markets at a specific location:
day-ahead market (DAM), hour-ahead scheduling process (HASP), real-time market (RTM).
Each price feed provides total price, loss price, energy price and congestion cost.

@author Andrew Krioukov
 conversion to smap-2.0
@author Stephen Dawson-Haggerty
'''

import zipfile
import urllib2
import StringIO
import BeautifulSoup
import datetime

import sys
import logging
import time
import threading
from operator import itemgetter, attrgetter

from zope.interface import implements

from smap.driver import SmapDriver
from smap.util import periodicSequentialCall
from smap.contrib import dtutil

class CaIsoPrice(SmapDriver):

  MARKETS = [('DAM', 30*60, 'Day-ahead market'),
             ('HASP', 10*60, 'Hour-ahead scheduling process'),
             ('RTM', 2*60, 'Real-time market')]
  FEEDS = [('total_price', '$', 'total price'),
           ('loss', '$', 'loss price'),
           ('congestion', '$', 'congestion price'),
           ('energy', '$', 'energy price')]

  def setup(self, opts):
    # get our location
    self.last_reading = {}
    for m, t, d in self.MARKETS:
      self.last_reading[m] = 0

    self.location = opts.get('Location', 'OAKLAND_1_N001')
    self.set_metadata('/', {
      'Location/Uri' : 'http://oasis.caiso.com/mrtu-oasis/SingleZip',
      'Extra/IsoNode' : self.location,
      'Extra/Driver' : 'smap.drivers.caiso_price.CaIsoPrice'
      })

    # add the feeds
    for (m, i, md) in self.MARKETS:
      for (f, u, fd) in self.FEEDS:
        path = '/%s/%s' % (m, f)
        self.add_timeseries(path, u, data_type='double',
                            description=md + ' ' + fd)

  def start(self):
    for (market, interval, description) in self.MARKETS:
      periodicSequentialCall(self.poll_stream, market, False).start(interval)

  def get_readings(self, market, start_date, stop_date): 
    readings = {'total_price': [], 'loss': [], 'energy': [], 'congestion': []}
    print "get_readings", market
    if market == 'DAM':
      q = 'PRC_LMP'
      m = 'DAM'
    elif market == 'HASP':
      q = 'PRC_HASP_LMP'
      m = 'HASP'
    elif market == 'RTM':
      q = 'PRC_INTVL_LMP'
      m = 'RTM'
    else:
      raise Exception("Invalid market: " + market)

    url = 'http://oasis.caiso.com/mrtu-oasis/SingleZip?'
    url += 'queryname=' + q
    url += '&startdate=' + dtutil.strftime_tz(start_date, '%Y%m%d', 'US/Pacific')
    url += '&enddate=' + dtutil.strftime_tz(stop_date, '%Y%m%d', 'US/Pacific')
    url += '&market_run_id=' + m
    url += '&node=' + self.location

    logging.info("Get url %s" % url)
    h = None
    for d in [5, 20, 60]:
      try:
        h = urllib2.urlopen(url, timeout=50)
        break
      except urllib2.URLError:
        logging.warn("urlopen failed.")
      time.sleep(d)
    if h == None:
      raise Exception("Failed to open url: %s" % url)

    z = zipfile.ZipFile(StringIO.StringIO(h.read()))
    xml = z.read(z.namelist()[0])
    b = BeautifulSoup.BeautifulSoup(xml)

    sec_per_int = int( b.find('m:sec_per_interval').contents[0] )

    rows = b.findAll('m:report_data')
    for d in rows:
      res = d.find('m:resource_name').contents[0]
      item = d.find('m:data_item').contents[0]
      day = d.find('m:opr_date').contents[0]
      inter = int( d.find('m:interval_num').contents[0] )
      val = float( d.find('m:value').contents[0] )

      secs = (inter - 1) * sec_per_int
      dt = dtutil.strptime_tz(day, '%Y-%m-%d', 'US/Pacific') + datetime.timedelta(seconds=secs)
      timestamp = dtutil.dt2ts(dt)

      key = None
      if item == 'LMP_PRC':
        key = 'total_price'
      elif item == 'LMP_LOSS_PRC':
        key = 'loss'
      elif item == 'LMP_ENE_PRC':
        key = 'energy'
      elif item == 'LMP_CONG_PRC':
        key = 'congestion'
      else:
        continue

      readings[key].append((timestamp, val))


    num_readings = len(readings[readings.keys()[0]])
    for k in readings.keys():
      if len(readings[k]) != num_readings:
        raise Exception('Missing readings')

      readings[k] = sorted(readings[k], key=lambda (t, v): t)

    return readings

  def poll_stream(self, market, load_old):
    def _push_data(readings, market): 
      # Zip together the values for all keys
      for vals in zip(*readings.values()):
        if vals[0][0] > self.last_reading[market]:
          # Add all smap points for this time
          for (k,v) in zip(readings.keys(), vals):
            logging.debug("add /%s/%s: %s" % (market, k, str(v)))
            self.add('/%s/%s' % (market, k), *v)
            self.last_reading[market] = vals[0][0]
            
    # Load old data
    if load_old == True:
      for day in range(1, 2):
        stop = dtutil.now() - datetime.timedelta(days=day)
        start = stop - datetime.timedelta(days=2)
        try:
          readings = self.get_readings(market, start, stop)
          _push_data(readings, market)
        except Exception, e:
          logging.exception('Error getting reading')

    # Continuously get new data
    try:
      stop = dtutil.now()
      start = stop - datetime.timedelta(days=1)

      readings = self.get_readings(market, start, stop)

      rt = readings['total_price'][-1][0]

      if rt > self.last_reading[market]:
        logging.info("NEW %s READING (%s) at time %s" %
                     (market, dtutil.strftime_tz(dtutil.ts2dt(rt), '%m/%d %H:%M', 'US/Pacific'),
                      dtutil.strftime_tz(dtutil.now(), '%m/%d %H:%M', 'US/Pacific')))
        _push_data(readings, market)
        # self.last_reading = rt

    except Exception, e:
      logging.exception('Error getting reading')

