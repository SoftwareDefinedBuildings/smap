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

import operator
import numpy as np

from smap.core import SmapException
from smap.operators import Operator, ParallelSimpleOperator, OP_N_TO_N
from smap.contrib import dtutil
from smap.ops.util import MaskedDTList

class SnapTimes(ParallelSimpleOperator):
    @staticmethod
    def _snaptimes(vec, bucketsz=300):
        vec[:,0] -= np.mod(vec[:,0], bucketsz)
        return vec
    base_operator = _snaptimes

    def __init__(self, inputs, windowsz):
        self.name = 'snaptimes-%i' % windowsz
        ParallelSimpleOperator.__init__(self, inputs,
                                        bucketsz=windowsz)


class DatetimeOperator(ParallelSimpleOperator):
    required_tags = set(['uuid', 'Properties/Timezone'])
    name = 'datetime'
    operator_name = 'datetime'
    operator_constructors = [()]

    def __init__(self, inputs):
        tz = set(map(operator.itemgetter('Properties/Timezone'), inputs))
        if len(tz) != 1:
            raise SmapException("Datetime operator only supports a single tz")
        self.tz = dtutil.gettz(list(tz)[0])
        self.base_operator = lambda vec: self._base_operator(vec)
        ParallelSimpleOperator.__init__(self, inputs)

    def _base_operator(self, vec):
        return zip(map(lambda x: dtutil.ts2dt(x).astimezone(self.tz), 
                       map(int, vec[:,0].astype(np.int))), vec[:, 1])


class DayOfWeekOperator(Operator):
    """Filter data by day of the week

    kwarg: days: a comma-separated list of ISO week days (1 - 7), 1 = Monday.  
      Default is to filter data for during the work week (M-F).

    Performance note: this function (at the moment) is implemented by
      doing a full timezone conversion on each timestamp; this
      performs rather poorly.  You are likly better off putting this
      late in the processing pipeline, after the data size has been
      reduced by more efficient operators.
    """
    name = 'dayofweek'
    operator_name = 'dayofweek'
    operator_constructors = [(), (str,)]

    def __init__(self, inputs, days="1,2,3,4,5"):
        self.days = map(int, days.split(','))
        self.tzs = map(lambda x: dtutil.gettz(x['Properties/Timezone']), inputs)
        Operator.__init__(self, inputs, OP_N_TO_N)

    def process(self, data):
        rv = []
        for i, vec in enumerate(data):
            ma = MaskedDTList(vec[:, 0], self.tzs[i])
            # find the days we're interested in
            takes = filter(None,
                           map(lambda (i, ts): i if ts.isoweekday() in self.days else None,
                               enumerate(ma)))
            rv.append(vec[takes, :])
        return rv
