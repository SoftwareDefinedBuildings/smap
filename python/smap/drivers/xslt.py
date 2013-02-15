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
Generic driver for XML sources.  Uses an XSLT transform to transform
the data into sMAP-XML.

@author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
"""

from twisted.internet import defer, threads
from twisted.python import log

import time
from lxml import etree
import urllib2
import urlparse

from smap import util, core
from smap.driver import FetchDriver
from smap.contrib import dtutil

class XMLDriver(FetchDriver):
    """Driver for generic XML documents.  They are expected to be in
    sMAP-XML format, which is basically the smap definitions directly
    mapped into XML.  To make this easier, you can apply an XSLT
    transformation to your document before processing with this
    module.

    Parameters:

    Xslt: path of XSLT stylesheet used to transform document.
        Optional if the source is already in sMAP-XML
    Timefmt = python strptime string used to parse the time in the
        document.  XSLTv1 doesn't have much in the way of time processing
        and anyways it's a pain to use.
    """
    def setup(self, opts):
        FetchDriver.setup(self, opts)      # set up the getter
        self.xslt = opts.get('Xslt', None) # transformation to be applied
        self.timefmt = opts.get("Timeformat", None)
        self.timezone = opts.get("Timezone", 'UTC')
        self.ignore_time = opts.get('IgnoreTimestamps', False)
        if self.xslt:
            with open(self.xslt, "r") as fp:
                self.xslt = etree.XSLT(etree.XML(fp.read()))

    def parse_val(self, ts, val):
        if ts['Properties']['ReadingType'] == 'long':
            return int(val)
        elif ts['Properties']['ReadingType'] == 'double':
            return float(val)
        else:
            return val

    def parse_time(self, ts, val):
        if self.timefmt == None:
            return int(val)
        else:
            return dtutil.dt2ts(dtutil.strptime_tz(val, self.timefmt, 
                                                   self.timezone))

    def make_jsonts(self, xmlts):
        """Transform a sMAP-XML Properties and Metadata section into json
        """
        ts = {
            'Properties': {'UnitofMeasure': ''},
            'Metadata': {},
            'Readings': []
            }
        for c in xmlts.getchildren():
            if c.tag == 'Properties':
                for p in c.getchildren():
                    if p.text != None: ts['Properties'][p.tag] = p.text 
            elif c.tag == 'Metadata':
                for cat in c.getchildren():
                    for field in cat.getchildren():
                        f = ts['Metadata'].get(cat.tag, {})
                        f[field.tag] = field.text 
                        ts['Metadata'][cat.tag] = f
        if not 'Timezone' in ts['Properties']:
            ts['Properties']['Timezone'] = self.timezone
        return ts

    def process(self, data):
        # maybe transform to smap-xml
        data = etree.XML(data)
        if self.xslt:
            data = self.xslt(data)

        for xmlts in data.getroot().getchildren():
            if not 'path' in xmlts.attrib:
                log.err("skipping timeseries: no path attribute")
                continue

            # maybe make/add a new timeseries if we haven't seen this one before
            path = xmlts.attrib['path']
            ts = self.get_timeseries(path)
            if not ts:
                ts = self.make_jsonts(xmlts)
                ts['uuid'] = self.uuid(path)
                ts = core.Timeseries(ts, None)
                self.add_timeseries(path, ts)

        for xmlts in data.getroot().getchildren():
            if not 'path' in xmlts.attrib:
                continue
            # add all of the readings
            path = xmlts.attrib['path']
            for r in xmlts.find('Readings').getchildren():
                try:
                    if not self.ignore_time:
                        rtime = self.parse_time(ts, r.find("Timestamp").text)
                    else:
                        rtime = time.time()
                    rval = self.parse_val(ts, r.find("Value").text)
                except (ValueError, TypeError), e:
                    log.err()
                    continue
                self._add(path, rtime, rval)
