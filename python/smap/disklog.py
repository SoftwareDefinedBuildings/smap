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

import os
import util
import time
from twisted.python import log

def snp(s):
    return "%08i" % s

class DiskLog:
    """Class which keeps an on-disk log of records
    """
    def _blank_meta(self):
        self.meta = {
                'head' : 0,
                'tail' : 0
                }


    def _write_meta(self):
        util.pickle_dump(os.path.join(self.dirname, 'META'), self.meta)

    def _read_meta(self):
        self.meta = util.pickle_load(os.path.join(self.dirname, 'META'))
        if self.meta == None: self._blank_meta()

    def _write_tail(self):
        util.pickle_dump(os.path.join(self.dirname, snp(self.meta['tail'] - 1)), self._tail)

    def _read_seqno(self, seq):
        try:
            return util.pickle_load(os.path.join(self.dirname, snp(seq)))
        except IOError, e:
            log.err("Warning: got exception reading sequence number: " + str(e))
            return None

    def __init__(self, dirname, max_age=None):
        self.dirname = dirname

        if not os.path.isdir(dirname):            
            # create a new log
            os.makedirs(dirname)
            self._blank_meta()
            self._write_meta()
            self._head = self._tail = None
        else:
            # read the head and tail off disk for an existing log
            self._read_meta()
            if self.meta['tail'] > 0:
                self._tail = self._read_seqno(self.meta['tail'] - 1)
            else:
                self._tail = None

            self._head = self._read_seqno(self.meta['head'])

        self.max_age = max_age
        self.dirty = False
            
    def __len__(self):
        return self.meta['tail'] - self.meta['head']

    def tail(self):
        """Return the tail of the log"""
        return self._tail

    def head(self):
        if self._head == None: self.pop()
        return self._head

    def update_tail(self, obj):
        # change the value of the tail
        self._tail = obj

        # if we're length 1, that's also the head
        if self.meta['tail'] == self.meta['head'] + 1:
            self._head = obj

        # need to sync
        self.dirty = True
    
    def append(self, obj):
        # flush the current tail to disk
        self.sync()

        # add the new tail (and head if we were empty)
        self._tail = obj
        if self.meta['tail'] == self.meta['head']:
            self._head = obj
        self.meta['tail'] += 1

        # need a flush
        self.dirty = True

    def sync(self):
        if self.dirty:
            self.dirty = False
            self._write_tail()
            self._write_meta()
            self._age_buffers()

    close = sync

    def pop(self):
        """Remove the head of the queue from disk"""
        readback = None
        while self.meta['tail'] > self.meta['head'] and readback == None:
            self._pop()
            readback = self._head
            if readback == None and self.meta['tail'] > self.meta['head']:
                # warn if there should have been something on disk
                log.err("WARN: disappeared log entry:" +
                        str(self.meta['head'] - 1))

    def _pop(self):
        self.sync()

        try:
            os.remove(os.path.join(self.dirname, snp(self.meta['head'])))
        except OSError:
            pass

        if self.meta['tail'] > self.meta['head']:
            self.meta['head'] += 1

        if self.meta['tail'] == self.meta['head']:
            # q is now empty
            self._head = self._tail = None
        elif self.meta['tail'] == self.meta['head'] + 1:
            # q now has length 1.  grab the head since it might be dirty
            self._head = self._tail
        else:
            # read the new head off disk
            self._head = self._read_seqno(self.meta['head'])

    def _age_buffers(self):
        """Remove buffers which have been on disk for longer than max_age"""
        if not hasattr(self, 'max_age') or self.max_age == None: return
        seqno = self.meta['head']
        now = time.time()
        for seqno in xrange(self.meta['head'], self.meta['tail'] + 1):
            try:
                mtime = os.path.getmtime(os.path.join(self.dirname, 
                                                      snp(self.meta['head'])))
            except OSError:
                break
            if now - mtime > self._total_seconds(self.max_age):
                self.pop()


    @staticmethod
    def _total_seconds(td):
        # timedelta.total_seconds is only available in python2.7
        return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 1e6) / 1e6
