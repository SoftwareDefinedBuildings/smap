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
