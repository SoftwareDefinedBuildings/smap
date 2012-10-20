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

import numpy as np
from smap.ops.arithmetic import _op_from_compressive_op

def _meter(data, reset_threshold=.1, axis=0):
    """Compute the total meter reading over an interval of timeseries
    data, attempting to correctly account for meter resets.

    The algorithm finds all of the regions in the time-series where
    the meter reading was increasing, and subtracts the starting value
    for each of these from the ending value.  It adds back all
    resetting values to account for the fact a meter should reset to
    zero.

    For instance, consider this stream of meter readings:
    10 11 12 .. 20 5 6 7

    The "meter reading" for this sequence should be 17.  It first
    increased from 10 to 20, for a total of 10, and then reset and
    increased from 5 to 7.  Because of the assumption it reset to
    zero, we add in 7 (instead of 2).

    """
    assert axis == 0
    # return zero if there is only zero (or one) value
    if data.shape[0] <= 1:
        return np.array([0])
    if len(data.shape) > 1:
        data = data[:, 0]

    reset_threshold = data[0] * reset_threshold
    restarts = np.nonzero((data[1:] - data[:-1]) < - reset_threshold )[0]
    starts = restarts + 1
    ends = restarts

    if data[1] < data[0] or not len(starts) or starts[0] != 0:
        starts = np.append(starts[::-1], 0)[::-1]

    if data[-1] < data[-2] or not len(ends) or ends[-1] != len(data) - 1:
        ends = np.append(ends, len(data) - 1)

    rv = np.sum(data[ends] - data[starts]) + np.sum(data[starts])
    if ends[0] != 0: rv -= data[0]
    return rv

meter = _op_from_compressive_op('meter', _meter)
