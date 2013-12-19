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

import operator

from smap import operators, util
from smap.archiver.data import escape_string

class AstNode(operators.Operator):
    def __init__(self, inputs, op, *children):
        self.op = op
        self.children = list(children)
        self.bind(inputs)

    def bind(self, inputs):
        for (i, c) in enumerate(self.children):
            self.children[i] = c(inputs)

        my_inputs = util.flatten((c.op.outputs for c in self.children))
        self.op = self.op(my_inputs)
        self.name = self.op.name
        operators.Operator.__init__(self, inputs, self.op.outputs)

    def process(self, data):
        return self.op(util.flatten((c.process(data) for c in self.children)))

    def __str__(self):
        return '%s[%s]' % (str(self.op), ','.join(map(str, self.children)))

class AstLeaf(AstNode):
    """A leaf node which just runs the base operator in input data
    """
    def bind(self, inputs):
        self.op = self.op(inputs)
        operators.Operator.__init__(self, inputs, self.op.outputs)

    def process(self, data):
        return self.op(data)


def nodemaker(op, *children):
    return lambda inputs: AstNode(inputs, op, *children)

def leafmaker(op, *children):
    return lambda inputs: AstLeaf(inputs, op, *children)

class Statement(object):
    OP_UUID = 0
    OP_HAS = 1
    OP_EQUALS = 2
    OP_LIKE = 3
    OP_REGEX = 4
    
    OP_AND = 5
    OP_OR = 6
    OP_NOT = 7

    def __init__(self, op, *args):
        self.op = op
        if self.op in [Statement.OP_UUID, Statement.OP_HAS, Statement.OP_EQUALS,
                       Statement.OP_LIKE, Statement.OP_REGEX]:
            self.args = tuple(map(escape_string, args))
        else:
            self.args = args

    def __iter__(self):
        """Iterate over all leaf statements"""
        if self.op in [Statement.OP_UUID, Statement.OP_HAS, Statement.OP_EQUALS,
                       Statement.OP_LIKE, Statement.OP_REGEX]:
            yield self
        else:
            for arg in self.args:
                for stmt in arg:
                    yield stmt
            yield self

    def render(self):
        if self.op == Statement.OP_UUID:
            return 's.uuid %s %s' % (self.args[0][1:-1], self.args[1])
        elif self.op == Statement.OP_HAS:
            return 's.metadata ? %s' % self.args
        elif self.op == Statement.OP_EQUALS:
            q = "(s.metadata -> %s) = %s" % self.args
            return  '(s.metadata ? %s) AND (%s)' % (self.args[0], q)
        elif self.op == Statement.OP_LIKE:
            q = "(s.metadata -> %s) LIKE %s" % self.args
            return  '(s.metadata ? %s) AND (%s)' % (self.args[0], q)
        elif self.op == Statement.OP_REGEX:
            q = "(s.metadata -> %s) ~ %s" % self.args
            return  '(s.metadata ? %s) AND (%s)' % (self.args[0], q)
        elif self.op == Statement.OP_AND:
            return '(%s) AND (%s)' % tuple(map(operator.methodcaller("render"), self.args))
        elif self.op == Statement.OP_OR:
            return '(%s) OR (%s)' % tuple(map(operator.methodcaller("render"), self.args))
        elif self.op == Statement.OP_NOT:
            return 'NOT (%s)' % tuple(map(operator.methodcaller("render"), self.args))

    def __str__(self):
        return str(self.op) + " " + str(self.args)
    

if __name__ == '__main__':
    import queryparse
    import uuid
    from smap import util
#
    op = queryparse.parse_opex("'/v_r' >= 3.3 + 2.68 * '/v_n' - [27.16 * ['/v_n' ^ 2]] < window(mean < rename('foo', 'bar'), field='minute') < units(all * 2 < rename('foo', 'x'), 'hp', 'W')  < rename('y', 'x') < rename('Path', 'y') ")
    # op = queryparse.parse_opex('sum < mean')
    # op = queryparse.parse_opex("rename('Path', 'x')")
    # op = queryparse.parse_opex("'/v_r' < rename('Path', 'x')")
    #op = queryparse.parse_opex("window(mean, field='minute')")
    c = op.ast([{'uuid': str(uuid.uuid1()),
                 'Path': '/v_r',
                 'Foo': 'bar',
                 'Properties/Timezone': 'America/Los_Angeles'},
                {'uuid': str(uuid.uuid1()),
                 'Path': '/v_n',
                 'Foo': 'bar',
                 'Properties/Timezone': 'America/Los_Angeles'}],)
# print c.get_restrictions(util.SetDict(op.restrict))
    print op
    print c
    # print util.SetDict(op.restrict)


