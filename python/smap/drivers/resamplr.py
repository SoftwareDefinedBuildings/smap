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

import uuid
import shelve
import time
import urllib
import pprint
import traceback
import datetime

import numpy as np

from smap.archiver.client import SmapClient
from smap.operators import *
from smap.contrib import dtutil
import smap.drivers.sumr as sumr
import smap.operators as opr

def _day_bin_equal(dt1, dt2):
    """Return true if two datetimes are in the same day"""
    return dt1.year == dt2.year and \
        dt1.month == dt2.month and \
        dt1.day == dt2.day

def _meter_sample(data, 
                  slop = datetime.timedelta(minutes=30),
                  bin_equal=_day_bin_equal,
                  # state parameters
                  prev=None,    # start of meter region
                  trianglestart=None, # last reset
                  accum=0,            # accumulated energy in window
                  prev_data=None):    # last point we saw
    rv = []
    if len(data) and (not prev or not trianglestart):
        prev = data[0]
        prev_data = data[0]
        trianglestart = data[0]
        accum = 0
        start = 1
    else:
        start = 0
    
    for i, v in enumerate(data[start:]):
        if v[1] < trianglestart[1]:
            # if we roll over, add in the accumulated sum through now
            accum += (prev_data[1] - trianglestart[1])
            trianglestart = v

        if bin_equal(prev[0], v[0]):
            # continue if we're still in the same bin
            prev_data = v
            continue
        elif bin_equal(prev[0], v[0] - slop) and \
                not bin_equal(prev[0] - slop, prev[0]):
            # otherwise produce a record if the endpoints are close to 

            accum += prev_data[1] - trianglestart[1]
            print "add", prev[0], accum, trianglestart[0]
            rv.append((dtutil.dt2ts(prev[0]), accum))
            prev_data = v

        prev = v
        trianglestart = v
        accum = 0

    return np.array(rv), {
        'prev' : prev,
        'prev_data' : prev_data,
        'trianglestart' : trianglestart,
        'accum' : accum
        }


class _MeterSampler(ParallelSimpleOperator):
    name = "meter-sampler"
    base_operator = staticmethod(_meter_sample)

class MeterSampler(CompositionOperator):
    name = "daily meter usage"
    chunksz = 60 * 15 
    # operator_name = 'meter'
    operator_constructors = [()]

    oplist = [
        lambda x: sumr.MissingSumOperator(x, MeterSampler.chunksz, 1.0),
        DatetimeOperator,
        _MeterSampler,
        ]
#     def __init__(self, inputs, a2):
#         # self.name = 'snaptimes-%i' % windowsz
#         ParallelSimpleOperator.__init__(self, inputs)


class MeterDriver(GroupedOperatorDriver):
    operator_class = MeterSampler


class SubsampleDriver(OperatorDriver):
    def setup(self, opts):
        """Set up what streams are to be subsampled.

        We'll only find new streams on a restart ATM.
        """
        self.restrict = opts.get("Restrict", 
                                 "has Path and (not has Metadata/Extra/SourceStream)")
        OperatorDriver.setup(self, opts, self.restrict, shelveoperators=False, raw=True)
        client = SmapClient(smapconf.BACKEND)
        source_ids = client.tags(self.restrict, 'uuid, Properties/UnitofMeasure')
        for new in source_ids:
            id = str(new['uuid'])
            if not 'Properties/UnitofMeasure' in new:
                new['Properties/UnitofMeasure'] = ''
            if not id in self.operators:
                o1 = SubsampleOperator([new], 300)
                self.add_operator('/%s/%s' % (id, o1.name), o1)
                o2 = SubsampleOperator([new], 3600)
                self.add_operator('/%s/%s' % (id, o2.name), o2)
