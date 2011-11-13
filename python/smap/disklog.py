
import util

import os
import shutil
import unittest

def snp(s):
    return "%08i" % s

class DiskLog:
    """Class which keeps an on-disk log of records
    """
    def _write_meta(self):
        util.pickle_dump(os.path.join(self.dirname, 'META'), self.meta)

    def _read_meta(self):
        self.meta = util.pickle_load(os.path.join(self.dirname, 'META'))

    def _write_tail(self):
        util.pickle_dump(os.path.join(self.dirname, snp(self.meta['tail'] - 1)), self._tail)

    def _read_seqno(self, seq):
        try:
            return util.pickle_load(os.path.join(self.dirname, snp(seq)))
        except IOError:
            return None

    def __init__(self, dirname):
        self.dirname = dirname

        if not os.path.isdir(dirname):            
            # create a new log
            os.makedirs(dirname)
            self.meta = {
                'head' : 0,
                'tail' : 0
                }
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

        self.dirty = False
            
    def __len__(self):
        return self.meta['tail'] - self.meta['head']

    def tail(self):
        """Return the tail of the log"""
        return self._tail

    def head(self):
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
            self._write_tail()
            self._write_meta()
            self.dirty = False

    close = sync

    def pop(self):
        """Truncate sequence numbers less than `seqno`
        """
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

    def idxtoseq(self, idx):
        pass


class TestDiskLog(unittest.TestCase):
    def test_1(self):
        try:
            dl = DiskLog("testdir")
            dl.append("FOO")
            self.assertEqual(dl.head(), "FOO")
            self.assertEqual(dl.tail(), "FOO")
        finally:
            shutil.rmtree("testdir")

    def test_save_one(self):
        try:
            dl = DiskLog("testdir")
            dl.append("FOO")
            self.assertEqual(dl.head(), "FOO")
            self.assertEqual(dl.tail(), "FOO")

            dl2 = DiskLog("testdir")
            self.assertEqual(dl.head(), "FOO")
            self.assertEqual(dl.tail(), "FOO")
        finally:
            shutil.rmtree("testdir")
        
    def test_append(self):
        try:
            dl = DiskLog("testdir")
            dl.append("FOO 0")
            for i in xrange(1, 10):
                self.assertEqual(dl.tail(), "FOO " + str(i-1))
                self.assertEqual(dl.head(), "FOO 0")
                dl.append("FOO " + str(i))
        finally:
            shutil.rmtree("testdir")

    def test_trunc(self):
        try:
            dl = DiskLog("testdir")
            dl.append("FOO 0")
            for i in xrange(1, 10):
                self.assertEqual(dl.tail(), "FOO " + str(i-1))
                self.assertEqual(dl.head(), "FOO 0")
                dl.append("FOO " + str(i))

            for i in xrange(1, 10):
                dl.pop()
                self.assertEqual(dl.head(), "FOO " + str(i))
        finally:
            shutil.rmtree("testdir")

    def test_trunc_split(self):
        try:
            dl = DiskLog("testdir")
            dl.append("FOO 0")
            for i in xrange(1, 10):
                self.assertEqual(dl.tail(), "FOO " + str(i-1))
                self.assertEqual(dl.head(), "FOO 0")
                dl.append("FOO " + str(i))
            dl.sync()
                
            dl2 = DiskLog("testdir")
            for i in xrange(1, 10):
                dl2.pop()
                self.assertEqual(dl2.head(), "FOO " + str(i))
        finally:
            shutil.rmtree("testdir")
            
    def test_race(self):
        try:
            dl = DiskLog("testdir")
            dl.append("FOO 0")
            for i in xrange(1, 10):
                self.assertEqual(dl.head(), "FOO " + str(i-1))
                self.assertEqual(dl.tail(), "FOO " + str(i-1))
                dl.append("FOO " + str(i))
                dl.pop()
            self.assertEqual(dl.head(), "FOO " + str(9))
            self.assertEqual(dl.tail(), "FOO " + str(9))
            dl.pop()
            self.assertEqual(dl.head(), None)
            self.assertEqual(dl.tail(), None)
        finally:
            shutil.rmtree("testdir")
        
    def test_edithead(self):
        try:
            dl = DiskLog("testdir")
            dl.append("FOO")
            self.assertEqual(dl.head(), "FOO")
            self.assertEqual(dl.tail(), "FOO")
            dl.update_tail("FOO BAR")
            self.assertEqual(dl.head(), "FOO BAR")
            self.assertEqual(dl.tail(), "FOO BAR")
        finally:
            shutil.rmtree("testdir")
        
    def test_edithead_2(self):
        try:
            dl = DiskLog("testdir")
            dl.append("FOO")
            self.assertEqual(dl.head(), "FOO")
            self.assertEqual(dl.tail(), "FOO")
            dl.append("FOO2")
            self.assertEqual(dl.tail(), "FOO2")
            dl.update_tail("FOO BAR")
            self.assertEqual(dl.tail(), "FOO BAR")

            dl.pop()
            self.assertEqual(dl.head(), "FOO BAR")
            self.assertEqual(dl.tail(), "FOO BAR")

        finally:
            shutil.rmtree("testdir")

    def test_pop(self):
        try:
            dl = DiskLog("testdir")
            dl.append("1")
            dl.append("2")
            self.assertEqual(dl.head(), "1")
            self.assertEqual(dl.tail(), "2")
            dl.pop()
            self.assertEqual(dl.head(), "2")
            self.assertEqual(dl.tail(), "2")
            dl.pop()
            self.assertEqual(dl.head(), None)
            self.assertEqual(dl.tail(), None)
        finally:
            shutil.rmtree("testdir")

    def test_big(self):
        try:
            dl = DiskLog("testdir")
            for i in xrange(0, 10):
                dl.append([i for i in xrange(0, 100000)])
        finally:
            shutil.rmtree("testdir")

        
if __name__ == '__main__':
    unittest.main()
