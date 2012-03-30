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

import numpy as np

from smap import operators
from smap.operators import null
from smap.ops.grouping import GroupByTimeOperator
from smap.ops.arithmetic import first

def ewma(inputs, alpha=0.9, prev=None):
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
    operator_name = 'subsample'
    operator_constructors = [(int, )]
    def __init__(self, inputs, period):
        self.name = 'subsample-' + str(period)
        GroupByTimeOperator.__init__(self, inputs, first, 
                                     chunk_length=period, snap_times=True)
