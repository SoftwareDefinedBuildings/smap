
import uuid
import shelve
import time
import urllib
import pprint
import traceback

import numpy as np

from smap.archiver.client import SmapClient
from smap.operators import *

def _subsample(vec, last=-1, bucketsz=5):
    if len(vec) == 0:
        return null, {'last' : last,
                      'bucketsz' : bucketsz}
    
    # ignore data before "last"
    vec[:, 0] -= np.mod(vec[:,0], bucketsz)
    times = vec[:,0]
    sp = np.where(times > last)
    if len(sp[0]) == 0: 
        return null, {'last': last,
                      'bucketsz': bucketsz}
    else: sp = sp[0][0]

    # add a dummy "last" ts
    times = np.hstack(([last], times[sp:]))
    # and bucket the times
    # we want the first point in each bucket
    takes = np.nonzero(times[1:] - times[:-1])
    rv = vec[takes[0] + sp]
    # rv[:,0] = times[1:]
    return rv, {'last': np.max(rv[:,0]), 
                'bucketsz' : bucketsz}

class SubsampleOperator(ParallelSimpleOperator):
    """Subsample N streams in parallel by taking the first reading
    that comes in within each bucket.
    """
    # the operator we'll parallelize across all input streams
    base_operator = staticmethod(_subsample)
    def __init__(self, inputs, windowsz):
        self.name = 'subsample-%i' % windowsz
        ParallelSimpleOperator.__init__(self, inputs, 
                                        bucketsz=windowsz)


class SubsampleDriver(OperatorDriver):
    def setup(self, opts):
        """Set up what streams are to be subsampled.

        We'll only find new streams on a restart ATM.
        """
        self.restrict = opts.get("Restrict", 
                                 "has Path and (not has Metadata/Extra/SourceStream)")
        OperatorDriver.setup(self, opts, self.restrict, shelveoperators=False)
        client = SmapClient(smapconf.BACKEND)
        source_ids = client.tags(self.restrict, 'distinct uuid')
        for new in source_ids:
            id = str(new[''])
            if not id in self.operators:
                o1 = SubsampleOperator([id], 300)
                self.add_operator('/%s/%s' % (id, o1.name), o1, '')
                o2 = SubsampleOperator([id], 3600)
                self.add_operator('/%s/%s' % (id, o2.name), o2, '')
