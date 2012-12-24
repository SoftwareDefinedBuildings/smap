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
import re
import numpy as np

from smap import operators
from smap.operators import null
from smap.ops.grouping import GroupByTimeOperator
from smap.ops.arithmetic import first

def ewma(inputs, alpha=0.9, prev=None):
    """Apply an EWMA to input data.  The EWMA is computed using the
    recursion:

T[0] = D[0]
T[i] = alpha * T[i-1] + (1 - alpha) * D[i]

D is the input data array.

Arg (optional, default=0.9): alpha.
"""
    if len(inputs) == 0:
        return null, {'alpha': alpha, 'prev': prev}

    inputs = np.array(inputs, dtype=float)
    if prev == None:
        prev = inputs[0][1]

    inputs[0][1] = alpha * prev + (1 - alpha) * inputs[0][1]
    for i in xrange(1, len(inputs)):
        inputs[i][1] = alpha * inputs[i - 1][1] + (1 - alpha) * inputs[i][1]

    return inputs, {'alpha': alpha, 'prev': inputs[-1][1]}

def movingavg(inputs, lag=10, hist=null):
    """Apply a windowed moving average to input data in terms of data
    points.

Arg (optional): the width of the window; default is 10.
"""
    inputs = np.array(inputs, dtype=float)
    data = np.vstack((hist, inputs))

    if len(data) < lag:
        return null, {'hist': data, 'lag': lag}

    # perform the windowed average using a convolution
    w = np.ones(lag) / lag
    avgs = np.convolve(w, data[:,1])[lag-1:-lag+1]
    output = np.vstack((data[lag-1:, 0], avgs)).T

    return output, {'hist': data[-lag+1:], 'lag': lag}

class MovingAverageOperator(operators.ParallelSimpleOperator):
    base_operator = staticmethod(movingavg)
    name = 'movingavg-'
    operator_name = 'movingavg'
    operator_constructors = [(),
                             (int,)]
    def __init__(self, inputs, lag=10):
        self.name = 'movingavg-' + str(lag)
        operators.ParallelSimpleOperator.__init__(self, inputs, lag=lag)

class EwmaOperator(operators.ParallelSimpleOperator):
    name = 'ewma'
    base_operator = staticmethod(ewma)
    operator_name = 'ewma'
    operator_constructors = [(),
                             (float,)]
    def __init__(self, inputs, alpha=0.9):
        self.name = 'ewma-' + str(alpha)
        operators.ParallelSimpleOperator.__init__(self, inputs, alpha=alpha)


class SubsampleOperator(GroupByTimeOperator):
    """Utility operator which subsamples by windowing in time, and
    taking the first reading in each window.
    """
    name = 'subsample'
    operator_name = 'subsample'
    operator_constructors = [(int, )]
    def __init__(self, inputs, period):
        GroupByTimeOperator.__init__(self, inputs, first, 
                                     chunk_length=period, 
                                     snap_times=True) 
        self.name = 'subsample-' + str(period)
        for i in xrange(len(self.inputs)):
            self.outputs[i]['uuid'] = str(uuid.uuid5(uuid.UUID(self.inputs[i]['uuid']), self.name))

class NonZeroOperator(operators.Operator):
    """Operator which only returns rows from input timeseries where a condition holds:

    Usage: nonzero(test_operator)

    test_operator will be applied to the input data; the input data
    will be returned wherever the condition evaluates to true

    Example:

    nonzero(greater(0)) 
       find data greater than zero

    """

    operator_name = 'nonzero'
    operator_constructors = [(lambda x: x,)]

    def __init__(self, inputs, filter):
        self.filter = filter(inputs)
        self.name = 'nonzero(%s)' % str(self.filter)
        operators.Operator.__init__(self, inputs, operators.OP_N_TO_N)

    def base_operator(self, data, takes):
        return data[np.nonzero(np.prod(takes[:, 1:], axis=1) )]

    def process(self, data):
        return [self.base_operator(*x) for x in zip(data, self.filter(data))]

class WhereOperator(operators.Operator):
    """Filter out a set of streams based on a tag name and value.
    """
    name = 'w'
    operator_name = 'w'
    operator_constructors = [(str, str)]

    def __init__(self, inputs, tag, pat):
        self.name = 'w(%s, %s)' % (tag, pat)
        pat = re.compile(pat)
        results = map(lambda x: pat.match(x.get(tag, '')), inputs)
        self.takes = [i for (i, elt) in enumerate(results) if elt]
        if len(self.takes) == 0:
            print "WARNING: no points found:", self.name
        operators.Operator.__init__(self, inputs, 
                                    [inputs[i] for i in self.takes])

    def process(self, data):
        return [data[i] for i in self.takes]
