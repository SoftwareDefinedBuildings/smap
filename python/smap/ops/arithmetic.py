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

Implement basic passthroughs for operators from numpy to ARQ.  There
are a few operator styles; some are row-wise, some are column-wise,
and some are element wise.  This module creates classes for them which
support operation in either dimension (where possible).

@author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
"""

from smap import operators
import numpy as np
from scipy import stats

def vector_operator_factory(name, op, constructors=[()], block_streaming=True):
    """Make a new vector operator class (type) from its name and operator"""
    classname = name.capitalize() + "VectorOperator"
    class Metaclass(type):
        def __new__(meta, _classname, bases, classdict):
            klass = type.__new__(meta, classname, bases, classdict)
            klass.base_operator = staticmethod(op)
            klass.name = name
            klass.operator_name = name
            klass.operator_constructors = constructors
            klass.block_streaming = block_streaming
            return klass

    class Op(operators.VectorOperator):
        __metaclass__ = Metaclass

    return Op

def _op_from_vector_ops(name, nameop, argop, constructors=[()]):
    """Generate a sMAP operator from a pair of operators which can
    work on either axis.

    Th
    """
    def _operator(data, *args, **kwargs):
        if not 'axis' in kwargs: kwargs['axis'] = 1
        if len(data) == 0: return operators.null
        if kwargs['axis'] == 0:
            return data.ix[argop(data.values, *args, **kwargs)]
        elif kwargs['axis'] == 1:
            return pd.DataFrame(nameop(data.values, *args, **kwargs), index=data.index)
    _operator.__doc__ = nameop.__doc__
    _opclass = vector_operator_factory(name, _operator, constructors)
    return _opclass

# arithmetic operators that have arg- versions.  using those we can
# pass along the timestamps
max = _op_from_vector_ops('max', np.max, np.argmax)
min = _op_from_vector_ops('min', np.min, np.argmin)

def _op_from_compressive_op(name, op, constructors=[()], timestamp=np.min):
    """Generate a sMAP operator from a single operator which can't
    pick a time stamp

    The input operators need to be "compressive" and only output one
    value for each input vector.  This means that they are not able to
    work in streaming mode.
    """
    def _operator(data, *args, **kwargs):
        if not 'axis' in kwargs: kwargs['axis'] = 1
        if len(data) == 0: return operators.null
        if kwargs['axis'] == 0:
            df = pd.DataFrame(op(data.values, *args, **kwargs), index=[timestamp(data.index.values)])
            #v = np.hstack(([timestamp(data[:, 0])], 
            #               op(data[:, 1:], *args, **kwargs)))
            #v = v.reshape((1, len(v)))
            return df
        elif kwargs['axis'] == 1:
            return pd.DataFrame(op(data.values, *args, **kwargs), index=data.index)
    _operator.__doc__ = op.__doc__
    _opclass = vector_operator_factory(name, _operator, constructors)
    _opclass.type = 'compressive'
    return _opclass

# for most operators the timestamps aren't super meaningful so doing
# something like taking the first one is sensible for column-wise
# operator.
# percentile = _op_from_compressive_op('percentile', np.percentile, [(float,)])
median = _op_from_compressive_op('median', np.median)
mean = _op_from_compressive_op('mean', np.mean)
sum = _op_from_compressive_op('sum', np.sum)
nansum = _op_from_compressive_op('nansum', np.nansum)
var = _op_from_compressive_op('var', np.var)
std = _op_from_compressive_op('std', np.std)
prod = _op_from_compressive_op('prod', np.prod)

nanmean = _op_from_compressive_op('nanmean', stats.nanmean)

# ufuncs operate element-by-element on arrays
#  these operators trivially support streaming
def _op_from_ufunc(name, op, constructors=[()]):
    def _operator(data, *args, **kwargs):
        if 'axis' in kwargs:
            del kwargs['axis']
        return op(data, *args, **kwargs)
    _operator.__doc__ = op.__doc__
    _opclass = vector_operator_factory(name, _operator, constructors,
                                       block_streaming=False)
    _opclass.type = 'ufunc'
    return _opclass

add = _op_from_ufunc('add', np.add, [(float,)])
multiply = _op_from_ufunc('multiply', np.multiply, [(float,)])
log = _op_from_ufunc('log', np.log)
log10 = _op_from_ufunc('log10', np.log10)
sqrt = _op_from_ufunc('sqrt', np.sqrt)
power = _op_from_ufunc('power', np.power, [(float,)])
exp = _op_from_ufunc('exp', np.exp)
absolute = _op_from_ufunc('absolute', np.absolute)
rint = _op_from_ufunc('rint', np.rint)
ceil = _op_from_ufunc('ceil', np.ceil)
floor = _op_from_ufunc('floor', np.floor)
trunc = _op_from_ufunc('trunc', np.trunc)
around = _op_from_ufunc('around', np.around)
clip = _op_from_ufunc('clip', np.clip, [(float, float)])

isnan = _op_from_ufunc('isnan', np.isnan)
greater = _op_from_ufunc('greater', np.greater, [(int,),(float,),])
greater_equal = _op_from_ufunc('greater_equal', np.greater_equal, [(int,),(float,)])
less = _op_from_ufunc('less', np.less, [(float,)])
less_equal = _op_from_ufunc('less_equal', np.less_equal, [(int,),(float,)])
equal = _op_from_ufunc('equal', np.equal, [(int,),(float,)])
not_equal = _op_from_ufunc('not_equal', np.not_equal, [(int,),(float,)])

def _diff(data, axis=1):
    """Compute discrete differences in either axis"""
    if axis == 1:
        return pd.DataFrame(np.diff(data, axis=1), index=data.index)
    else:
        return data.diff()
    
diff = vector_operator_factory('diff', _diff)

def _first(data, axis=0):
    """Return the first column or the first row of data.
    """
    if axis == 1:
        return data.iloc[:,0]
    elif axis == 0:
        return data.iloc[0] if len(data) > 0 else operators.null

first = vector_operator_factory('first', _first, block_streaming=False)

def _count(data, axis=0):
    """Return the number of rows or columns of data"""
    shape = np.shape(data)
    if axis == 0:
        return len(data)
    elif axis == 1: 
        #this is weird but ok.
        return np.ones(len(data)) * len(data.columns)
        
count = _op_from_compressive_op('count', _count)

def _product(data, axis=0):
    #TODO start here.
    if axis == 0:
        return reduce(np.multiply, data[1:], data[0, :])
    if axis == 1:
        return reduce(np.multiply, data.T[1:], data[:, 0])
product = _op_from_compressive_op('product', _product)


