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

import os
import logging
import shelve
import pickle
import numpy as np

CACHEDIR='.cache'

def from_key(s):
    x = s.split('-')
    return (int(x[0]), int(x[1]))

def filter_data(range, data):
    idx = (data[:,0] >= range[0]) & (data[:,0] <= range[1])
    return data[np.nonzero(idx)]

class TimeseriesCache:
    """Cache of timeseries data.

    A time series cache allows clients to store on disk a single
    time-series (a sequence of time, value tuples) and read back
    ranges.  If only part of the data is available, the cache will
    return the segments so the application can query the data store
    for the remaining data, and presumably insert it into the cache.
    """
    def __init__(self, identifier, ondisk=True):
        self.log = logging.getLogger("TimeseriesCache")
        if ondisk:
            try:
                os.makedirs(CACHEDIR)
            except OSError:
                pass
            self.cache = shelve.open(os.path.join(CACHEDIR, identifier), 
                                     protocol=2)
        else:
            self.log.info("Using non-persistant cache")
            self.cache = {}

    def close(self):
        self.cache.close()

    def clear(self):
        self.cache.clear()
        self.cache.sync()

    def insert(self, substream, start, end, data):
        """Insert new data into the cache
        """
        key = "%i-%i" % (start, end)
        substream = str(substream)
        if len(data) == 0: return
        if not self.cache.has_key(substream):
            self.cache[substream] = {key:  data}
        else:
            # do this due to copy issues with shelve
            ssdata = self.cache[substream]
            ssdata[key] = data
            self.cache[substream] = ssdata
        self.cache.sync()

    def set_meta(self, meta):
        self.cache['meta'] = meta
        self.cache.sync()

    def get_meta(self):
        return self.cache.get('meta')

    def read(self, substream, start, end):
        """Read back fragments of data from the cache in the range [start, end] (inclusive)
        """
        pointer = 0
        substream = str(substream)
        rv = []
        if not substream in self.cache:
            return []

        for k in sorted(self.cache[substream].keys(), key=lambda k: from_key(k)[0]):
            (s,e) = from_key(k)
            key = None
            if s <= start and e > start:
                key = (max(pointer, start), min(e, end))
            elif s >= start and s < end:
                key = (max(pointer, s), min(e, end))

            if key != None and key[1] > pointer:
                pointer = key[1]
                rv.append((key, filter_data(key, self.cache[substream][k])))
        return rv

