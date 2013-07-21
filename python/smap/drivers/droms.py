"""
Copyright (c) 2013 Regents of the University of California
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
Driver for posting windowed, averaged power data to DROMS

@author Tyler Hoyt <thoyt@berkeley.edu>
"""

import requests
import sys
import zipfile

import smap.sjson as json
from smap.driver import SmapDriver
from smap.util import periodicSequentialCall, split_path, join_path
from smap.contrib import dtutil
from smap.archiver.client import parser

from twisted.internet import threads

class Driver(SmapDriver):
    def setup(self, opts):
        self.url = opts.get('url')
        self.key = opts.get('key')
        self.paths = opts.get('Paths', default_paths)
        self.expr = opts.get('Expr', "window(mean, field='minute', width=15)")
        self.rate = float(opts.get('Rate', 60))
        self.user = opts.get('User')
        self.password = opts.get('Password')
        self.auth = requests.auth.HTTPBasicAuth(self.username, self.password)
        self.params = {'key': key } 

    def start(self):
        periodicSequentialCall(self.read).start(self.rate)

    def read(self):
        restrict = "Path='" + "' or Path='".join(self.paths) + "'"
        query = "apply %s to data in (now -15m, now) where (%s)" % (self.expr, restrict)
        r = requests.post(self.url, data=query, params=self.params)
        self._value = zip(self.paths, json.loads(r.text))
        self.writeDROMScsv(self._value)
        self.writeDROMSzip()
        self.postDROMSzip()

    def writeDROMScsv(self, value):
        fcsv = open('meterdata.csv','w')
        fcsv.write(','.join(['DateTime', 'MeterId', 'Value1', 'Value2']) + '\n')
        for path, val in value:
            if not 'Readings' in val: continue
            cmps = split_path(path)
            channel = join_path(cmps[1:])
            for d in val['Readings']:
                if d is None: continue
                ts = dtutil.strftime_tz(dtutil.ts2dt(d[0] / 1000), "%Y-%m-%d %H:%M", tzstr='Local')
                if ts is None: continue
                v = d[1] 
                if v is None: continue
                if val['Properties']['UnitofMeasure']=='Watts': v /= 1000.
                v /= 4. # approximate kWh
                fcsv.write(','.join([ts,channel,str(v)]) + '\n')
        fcsv.close()

    def writeDROMSzip(self):
        z = zipfile.ZipFile('meterdata.zip','w')
        z.write('meterdata.csv')
        z.close()

    def postDROMSzip(self):
        tenant_url = self.url
        api_path = "api/v1/meters"
        files = {'file': ('meterdata.zip', open('meterdata.zip', 'rb'))}
        url = tenant_url + api_path
        print url
        r = requests.post(url, auth=self.auth, files=files)
        print r.text
