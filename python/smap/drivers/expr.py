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
import operator
import itertools
import numpy as np
import time
import traceback

from twisted.internet import threads
from twisted.python import log

from smap import core, util
from smap.driver import SmapDriver
from smap.archiver.queryparse import parse_opex
from smap.archiver.client import SmapClient
from smap.operators import null, OperatorDriver
from smap.ops.grouping import GroupByTagOperator

class ExprDriver(OperatorDriver):
    """Driver which computes an operator on a set of input streams

Configuration options:
 Expression(.*): operator expressions to compute
 Where: where-clause specifying the input streams
 Group: tag name indicating any grouping necessary
    """
    def setup(self, opts):
        OperatorDriver.setup(self, opts)
        self.restrict = opts.get('Restrict')
        self.group = opts.get('Group', None)
        self.tz = opts.get('Timezone', core.Timeseries.DEFAULTS['Properties/Timezone'])

        # specialize the input operators
        self.ops = []
        for k, v in opts.iteritems():
            if not k.startswith('Expression'): continue
            self.ops.append(parse_opex(v))

    def start(self):
        d = threads.deferToThread(self.load_tags)
        d.addCallback(self.add_operators)
        d.addCallback(lambda _: OperatorDriver.start(self))
        return d

    def load(self, *args, **kwargs):
        d = threads.deferToThread(self.load_tags)
        d.addCallback(self.add_operators)
        d.addCallback(lambda _: OperatorDriver.load(self, *args, **kwargs))
        return d

    def load_tags(self):
        """Load the matching tags (in a thread)"""
        c = SmapClient(self.source_url)
        return c.tags(self.restrict)

    def add_operators(self, tags):
        """Once we've figured out what the input streams are, we can
        bind the specialized operators to the individual input
        streams"""
        self.operators = {}
        i = 0
        groups = {} 
        for s in tags:
            key = s.get(self.group, None)
            if not key in groups: groups[key] = []
            groups[key].append(s)

        self.loading = True
        for g, inputs in groups.iteritems():
            print "adding group", g, "(%i/%i)" % (i, len(groups))
            i += 1
            for op in self.ops:
                op_instance = op.ast(inputs)
                assert len(op_instance.outputs) == 1
                try:
                    inp = map(operator.itemgetter('uuid'), op_instance.inputs)
                    out = op_instance.outputs[0]
                    path = '/' + '.'.join(map(str, sorted(inp))) + '/' + str(out['uuid'])
                    self.add_operator(path, op_instance)
                except:
                    traceback.print_exc()
                    raise

                try:
                    log.msg("[" + ','.join(map(operator.itemgetter('uuid'), op_instance.inputs)) + 
                            '] -> [' +  
                            ','.join(map(operator.itemgetter('uuid'), op_instance.outputs)) + ']')
                except:
                    pass

        self.loading = False
