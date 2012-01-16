
import uuid
import numpy as np

from smap.archiver.client import SmapClient
from smap.operators import *
from smap.drivers.resamplr import SubsampleOperator

def _mean(vec):
    """Take the mean of both the timestamps and the values"""
    if len(vec) == 0:
        return null, {}
    else:
        return np.array([np.mean(vec, axis=0)]), {}

def join(inputs, last=None):
    """Join together streams based on timestamps, throwing out places
    where they do not overlap"""
    times = reduce(lambda x, y: np.intersect1d(x, y[:,0]), inputs)
    vals = map(lambda x: x[np.nonzero(np.in1d(x[:,0], times)), :][0]
               if len(x) else null, inputs)
    return vals 


def joinedop(op, inputs):
    vals = op(map(lambda x: x[:,1], inputs), axis=0)
    return [np.dstack((inputs[0][:,0], vals))[0]]

joinedsum = lambda _, input: joinedop(np.sum, input)
joinedmean = lambda _, input: joinedop(np.mean, input)
joinedmedian = lambda _, input: joinedop(np.median, input)

###
###
### Operators
###
###

##
## Buffering operators. BufferedJoinOperator and LatestOperator are
## often placed at the head of the processing chain, so later
## operators can operate on windows of data.
##
class BufferedJoinOperator(Operator):
    """This operator takes an arbitrary number of streams as input,
    and combines them by joining on timestamp.  It keeps a
    variable-size join buffer in case readings come at different
    rates.
    """
    name = "buffered join"
    maxbufsz = 100
    joinmethod = staticmethod(join)

    def __init__(self, inputs):
        Operator.__init__(self, inputs, outputs=OP_N_TO_N)
        self.pending = [null] * len(inputs)
        self.last = -1

    def process(self, input):
        # add new data to the pending map
        self.pending = map(lambda (x, y): np.vstack((x,y)),
                           zip(self.pending, input))
        # find what data we can deliver
        output = self.joinmethod(self.pending, last=self.last)
        # and filter out data we no longer need
        if len(output[0]):
            self.last = np.max(output[0][:, 0])
            self.pending = map(lambda x: x[np.nonzero(x[:, 0] > self.last)],
                               self.pending)
        # truncate buffer
        self.pending = map(lambda x: x[-self.maxbufsz:], self.pending)
        return output

class LatestOperator(Operator):
    """Keep a window of up to max_age for each input stream.  Output
    all buffered data whenever any stream receives data -- this means
    repeats."""
    name = "latest buffer operator"
    def __init__(self, inputs, max_age=10):
        Operator.__init__(self, inputs, outputs=OP_N_TO_N)
        self.pending = [null] * len(inputs)
        self.max_age = max_age

    def process(self, input):
        produce = False
        # store the new data
        for i in xrange(0, len(input)):
            if len(input[i]):
                self.pending[i] = np.vstack((self.pending[i], input[i]))
                produce = True

        # filter out old readings
        maxts = max(map(lambda x: np.max(x[:, 0] if len(x) else 0), 
                        self.pending))
        self.pending = map(lambda x: x[np.nonzero(x[:, 0] > maxts - self.max_age)] 
                           if len(x) else null, 
                           self.pending)
        return self.pending

##
## Mean operators with different semantics
##
class _MeanOperator(Operator):
    """Mean operator which requires all data to be present and
    timestamps to be aligned"""
    name = 'mean'
    process = staticmethod(joinedmean)

class _MissingMeanOperator(Operator):
    """Take the mean of each row of data.  Each input vector should
    either have the same number of entries or be of length zero.  This
    operator will produce the mean across all input data with data, as
    long as more than `ndatathresh` percent of input streams have data;
    otherwise it will produce nothing.
    """
    name = 'mean with missing'
    ndatathresh = 0.6
    def process(self, input):
        meandata = [x for x in input if len(x)]
        if float(len(meandata)) / len(self.inputs) > self.ndatathresh:
            return [joinedmean(None, meandata)]
        else:
            return [null]

class _MeanVectorOperator(ParallelSimpleOperator):
    """Take the mean of all data presented from N feeds"""
    name = 'mean vector'
    base_operator = staticmethod(_mean)


class _SumOperator(Operator):
    name = 'sum'
    process = joinedsum

##
## Subsampling operators
##
##
## Useful operators made up of streams of other operators
##
class SubsampledSumOperator(CompositionOperator):
    """Add up N streams by first bucketing and then buffering data
    until data from all streams are present.
    """
    name = 'subsampled sum'

    def __init__(self, inputs, windowsz):
        self.windowsz = windowsz
        self.oplist = [lambda inputs: SubsampleOperator(inputs, self.windowsz),
                       BufferedJoinOperator,
                       _SumOperator]
        CompositionOperator.__init__(self, inputs)


class SubsampledMeanOperator(CompositionOperator):
    oplist = [lambda inputs: SubsampleOperator(inputs, 300),
              BufferedJoinOperator,
              _MeanOperator]

class RunningBucketMeanOperator(CompositionOperator):
    """Maintain a mean of N streams where not all of them are present
    """
    name = 'Running bucketed mean operator'
    def __init__(self, inputs, window=300):
        CompositionOperator.__init__(self, inputs)
        self.window = window
        self.oplist = [
            # first keep only a window        
            lambda x: LatestOperator(x, self.window),
            
            # output the mean of all the data in the window
            _MeanVectorOperator, 

            # then take the mean across all feeds
            _MissingMeanOperator, 
        
            # output one record every 5 minutes for each stream
            lambda x: SubsampleOperator(x, self.window),
            ]

class DefaultSummationDriver(GroupedOperatorDriver):
    def setup(self, opts):
        windowsz = opts.get("Window", 300)
        if not "Restrict" in opts:
            opts["Restrict"] = "Metadata/Extra/ServiceRegion = 'building'"
        if not "Group" in opts:
            opts["Group"] = "Metadata/Location/Building"
        self.operator_class = (lambda x: SubsampledSumOperator(x, windowsz))
        GroupedOperatorDriver.setup(self, opts)

def MeanDriver(GroupedOperatorDriver):
    self.operator_class = RunningBucketMeanOperator
        
if __name__ == '__main__':
    import uuid
    import sys
    from smap.core import SmapInstance
    from smap.server import run

    inst = SmapInstance('199f4dea-3fe7-11e1-a873-279f694929ec')
    d = DefaultSummationDriver(inst, '/test', uuid.UUID('37b920ee-3fe7-11e1-b2a9-ab84ef095b88'))
    d.setup({})
    inst.add_driver('/test', d)

    run(inst)
    sys.exit()

    # op = SubsampleOperator(['42fba228-3e53-11e1-a2e9-c3a912c02386',
    #                         '42fba228-3e53-11e1-a2e9-c3a912c02382'], 10)
    # print op.name, op.uuid
#     boo = BufferedJoinOperator(['42fba228-3e53-11e1-a2e9-c3a912c02382',
#                                 '42fba228-3e53-11e1-a2e9-c3a912c02386'])

    sz = 1000
    dat = np.zeros((sz, 2))
    dat[:,0] = np.arange(0, sz)
    dat[:,1] = np.arange(0, sz)
    
#     print boo.inputs
#     print boo.outputs
    
    
    co = SubsampledSumOperator(['42fba228-3e53-11e1-a2e9-c3a912c02382',
                                '42fba228-3e53-11e1-a2e9-c3a912c02386'])
#     print co([null, dat])
#     print co([dat, null])
    #print co([dat, dat])
    
    mp = _MeanVectorOperator(['42fba228-3e53-11e1-a2e9-c3a912c02382',
                              '42fba228-3e53-11e1-a2e9-c3a912c02386'])
    #print mp.inputs, mp.outputs
    #print "means", mp([dat, dat])

    sz = 20
    dat2 = np.zeros((sz/2, 2))
    dat2[:,0] = np.arange(0, sz, 2)
    dat2[:,1] = np.arange(0, sz, 2)

    dat3 = np.zeros((sz/3+1, 2))
    dat3[:,0] = np.arange(0, sz, 3)
    dat3[:,1] = np.arange(0, sz, 3)

    lo = LatestOperator(['42fba228-3e53-11e1-a2e9-c3a912c02382',
                         '42fba228-3e53-11e1-a2e9-c3a912c02386'])
    # print lo([dat2, dat3])

    rbmo = RunningBucketMeanOperator(['42fba228-3e53-11e1-a2e9-c3a912c02382',
                                      '42fba228-3e53-11e1-a2e9-c3a912c02386'], 20)
    
    print rbmo([dat2, null])
    print rbmo([null, dat3])
    print rbmo([null, dat3])
    
#     # op([dat, null])
#     # op([null, dat])

#     print joinedsum(join([dat, dat2, dat3]))
#     print joinedmean(join([dat, dat2, dat3]))
#     print joinedmedian(join([dat, dat2, dat3]))

