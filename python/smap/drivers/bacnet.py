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
@author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
"""

import json
import re
import operator
import sys

from twisted.internet import threads, defer

from smap.driver import SmapDriver
from smap.util import periodicSequentialCall
from smap.iface.pybacnet import bacnet

def _get_class(name):
  cmps = name.split('.')
  assert len(cmps) > 1
  (mod_name, class_name) = ('.'.join(cmps[:-1]), cmps[-1])
  if mod_name in sys.modules:
      mod = sys.modules[mod_name]
  else:
      mod = __import__(mod_name, globals(), locals(), [class_name])
  return getattr(mod, class_name)

class BACnetDriver(SmapDriver):
    """Driver for polling BACnet points"""
    def setup(self, opts):
        bacnet.Init(opts.get('iface', 'eth0'), '47900')
        with open(opts.get('db'), 'r') as fp:
            self.db = json.load(fp)
        self.rate = int(opts.get('rate', 60))
        self.devices = map(re.compile, opts.get('devices', ['.*']))
        self.points = map(re.compile, opts.get('points', ['.*']))
        self.ffilter = _get_class(opts.get('filter')) if opts.get('filter') else None
        self.pathnamer = _get_class(opts.get('pathnamer')) if opts.get('pathnamer') else None
        for (dev, obj, path) in self._iter_points():
            unit = str(obj['unit']).strip()
            if unit.isdigit():
                unit = str(bacnet.type_str(int(unit)))
            self.add_timeseries(path, unit, data_type='double')

    @staticmethod
    def _matches(s, pats):
        return len(filter(None, map(lambda p: p.match(s), pats))) > 0

    def get_path(self, dev, obj):
        if self.pathnamer:
            path = str(self.pathnamer(dev['name'], obj['name']))
        else:
            path = str('/' + dev['name'] + '/' + obj['name'])
        return (dev, obj, path)

    def _iter_points(self):            
        for dev in self.db:
            if self.ffilter:
                for obj in dev['objs']:
                    if self.ffilter(dev['name'], obj['name']):
                        yield self.get_path(dev, obj)
            else: 
                if not self._matches(dev['name'], self.devices): continue
                for obj in dev['objs'][1:]:
                    if not self._matches(obj['name'], self.points): continue
                    yield self.get_path(dev, obj)

    def start(self):
        self.caller = periodicSequentialCall(self.update)
        self.caller.start(self.rate)

    @defer.inlineCallbacks
    def update(self):
        for (dev, obj, path) in self._iter_points():
            try:
                val = yield threads.deferToThread(bacnet.read_prop,
                                                  dev['props'],
                                                  obj['props']['type'],
                                                  obj['props']['instance'],
                                                  bacnet.PROP_PRESENT_VALUE,
                                                  -1)
            except IOError:
                pass
            else:
                self._add(path, float(val))
