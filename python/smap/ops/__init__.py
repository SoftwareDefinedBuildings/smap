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

import sys
import inspect

from twisted.spread import pb

from smap import operators

__all__ = [
    'smap.operators',
    'smap.ops.grouping',
    'smap.ops.arithmetic',
    'smap.ops.filters',
    'smap.ops.meter',
    'smap.ops.util',
    'smap.ops.ts',
    ]
map(__import__, __all__)

installed_ops = {}

def discover():
    for m in __all__:
        for name, obj in inspect.getmembers(sys.modules[m]):
            if inspect.isclass(obj) and \
                    issubclass(obj, operators.Operator):
                if  hasattr(obj, "operator_name"):
                    installed_ops[obj.operator_name] = obj

                # register all operators with the perspective broker
                # so we can remote-call them if we want to.
                pb.setUnjellyableForClass(obj, obj)

    # print "found ops:", ', '.join(sorted(installed_ops.iterkeys()))

discover()
