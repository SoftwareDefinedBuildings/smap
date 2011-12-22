#!/usr/bin/env python
'''
sMAP feed for BPA Total Wind, Hydro, and Thermal Generation.
@author Gabe Fierro
'''
import urllib2

import logging
from smap.driver import SmapDriver
from smap.util import periodicSequentialCall
from smap.contrib import dtutil

class BPADriver(SmapDriver):
	'''
	Scrape feed from BPA site and parse as a sMAP feed. BPA updates approximately every 5 minutes so we
	update every 2.5 minutes to make sure we catch all the updates (updates are correctly timestamped
	in increments of 5 minutes). We parse wind, hydro and thermal feeds.
	'''
	def setup(self, opts):

		self.w = self.add_timeseries('/wind','MW',description='Total Wind Generation')
		self.h = self.add_timeseries('/hydro','MW',description='Total Hydro Generation')
		self.t = self.add_timeseries('/thermal','MW',description='Total Thermal Generation')
		self.l = self.add_timeseries('/load','MW',description='Total Load')
		self.set_metadata = {
			'Location' : {'State': 'WA', 'Uri': 'http://transmission.bpa.gov/business/operations/wind/baltwg.txt'}
			}
		self.previousTime = 0
		
	def start(self):
		periodicSequentialCall(self.read).start(5*30) # updates every 2.5 minutes
		
	def read(self):
		object_ = {}
		print 'read running'
		try:
			#get the text from the ur
			wa = urllib2.urlopen('http://transmission.bpa.gov/business/operations/wind/baltwg.txt')
			data = [line for line in wa.readlines()[7:] if len(line.split()) > 3]
			#parse most recent data
			rawTime = " ".join(data[-1].split()[:2])
			currentTime = int(dtutil.dt2ts(dtutil.strptime_tz(rawTime,"%m/%d/%Y %H:%M",'US/Pacific')))
			object_["Wind"] = data[-1].split()[3]
			object_["Hydro"] = data[-1].split()[4]
			object_["Thermal"] = data[-1].split()[5]
			object_["Load"] = data[-1].split()[2]
		except Exception as e:
			logging.exception(type(e))
			print e
		else:
			if currentTime != self.previousTime:
				self.w.add(currentTime,int(object_["Wind"]))
				self.h.add(currentTime,int(object_["Hydro"]))
				self.t.add(currentTime,int(object_["Thermal"]))
				self.l.add(currentTime,int(object_["Load"]))
				self.previousTime = currentTime
			wa.close()
