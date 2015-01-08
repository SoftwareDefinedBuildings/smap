"""
Copyright (c) 2014 Building Robotics, Inc.
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

import copy
import operator
from smap.operators import Operator

class SetKeyOperator(Operator):
    """Sets a key on all output streams

    For instance, adding a:

      set_key("Metadata/Extra/Name", "Foo")

    To the operator pipeline will set the Metadata/Extra/Name tag to
    "Foo" on all input streams.
    """
    name = 'set_key'
    operator_name = 'set_key'
    operator_constructors = [(str, str)]

    def __init__(self, inputs, key, value):
        # don't change uuids
        outputs = copy.deepcopy(inputs)
        for o in outputs:
            o[key] = value
        Operator.__init__(self, inputs, outputs)

    def process(self, inputs):
        return inputs

    def sketch(self):
        return "null"

class ConsistentSetKeyOperator(SetKeyOperator):
    name = operator_name = 'tag_copy'

class RenameOperator(Operator):
    """Rename a tag to a new value.
    """
    name = 'rename'
    operator_name = 'rename'
    operator_constructors = [(str, str)]

    def __init__(self, inputs, tag, newname, remove=True):
        self.name = 'rename(%s, %s)' % (tag, newname)
        output = copy.deepcopy(inputs)
        for s in output:
            if tag in s:
                s[newname] = s[tag]
                if remove: 
                    del s[tag]
        Operator.__init__(self, inputs, output)

    def process(self, data):
        return data

    def sketch(self):
        return "null"

class ConistentRenmeOperator(RenameOperator):
    name = operator_name = 'tag_rename'

class CopyTagOperator(RenameOperator):
    """Copy the values of a tag to a new tag name
    """
    name = operator_name = 'tag_copy'

    def __init__(self, inputs, tag, newname, remove=False):
        RenameOperator.__init__(self, inputs, tag, newname, remove=remove)

    def sketch(self):
        return "null"

class TagPick(Operator):
    """ "Pick" streams by tag value

    For instance, 

      pick("c9001605-2e11-5145-a331-48f7532c95b7", "33aafbe6-4dc0-11e4-a560-b8e856313136") 

    will find the input stream with the two relevant UUIDs and output
    them in that order.

    This operator will raise an error if any of the provided values do
    not match.  If multiple streams match, only one will be included.

    The default tag to match on is 'uuid'; however, you may specify
    others using the 'tag=' kwargs.  For instance:

    
    """
    name = 'pick'
    operator_name = 'pick'
    operator_constructors = []
    varardic = True

    def __init__(self, inputs, *vals, **kwargs):
        tag = kwargs.get('tag', 'uuid')
        keys = map(lambda x: x.get(tag, None), inputs)
        self.order = map(lambda val: keys.index(val), vals)
        Operator.__init__(self, inputs, [inputs[i] for i in self.order])

    def process(self, data):
        return map(lambda i: data[i], self.order)

    def sketch(self):
        return "null"
