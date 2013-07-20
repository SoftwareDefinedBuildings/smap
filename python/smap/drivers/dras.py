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
Simplest possible DRAS client as a sMAP driver

@author Tyler Hoyt <thoyt@berkeley.edu>
"""

import requests
from lxml import etree

from smap.driver import SmapDriver
from smap.util import periodicSequentialCall

class Driver(SmapDriver):
    def setup(self, opts):
        self.add_timeseries('/EventStatus','binary')
        self.url = opts.get('url')
        self.username = opts.get('Username')
        self.password = opts.get('Password')
        self.rate = float(opts.get('Rate', 60))
        self.s = requests.Session()
        self.s.auth = (self.username, self.password)
        self.prev = False
        dr_modname = opts.get('DR_sequence')
        dr_modname = dr_modname.split('.')
        dr_classname = dr_modname.pop()
        dr_modname = '.'.join(dr_modname)
        dr_mod = __import__(dr_modname, fromlist=[dr_classname])
        klass = getattr(dr_mod, dr_classname)
        self.dr = klass()

    def start(self):
        periodicSequentialCall(self.read).start(self.rate)

    def read(self):
        r = self.s.get(self.url, verify=False)
        e = etree.fromstring(r.text)
        print r.text
        for t in e.iter():
            if 'EventStatus' in t.tag:
                status = t.text
                break

        active = status=='ACTIVE'
        val = 1 if active else 0
        self.add('/EventStatus', val)
        if active and not self.prev:
            self.dr.respond()
        if not active and self.prev:
            self.dr.revert()
        
        self.prev = active
