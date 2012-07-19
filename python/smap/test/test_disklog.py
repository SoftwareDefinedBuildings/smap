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

import time
import datetime
import os
import glob
from smap.disklog import DiskLog
from twisted.trial import unittest

import shutil

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

    def test_aging(self):
        try:
            max_age = datetime.timedelta(seconds=1)
            dl = DiskLog("testdir", max_age)
            for i in xrange(0, 10):
                dl.append(str(i))
            dl.sync()
            self.assertEqual(dl.head(), "0")
            time.sleep(2)
            dl.append("11")
            dl.sync()
            self.assertEqual(dl.head(), "11")
        finally:
            shutil.rmtree("testdir")

    def test_disappearing_logs(self):
        try:
            dl = DiskLog("testdir")
            for i in xrange(0, 10):
                dl.append(i)
            dl.sync()

            # head is cached even though we removed it
            os.remove("testdir/00000000")
            os.remove("testdir/00000001")
            self.assertEqual(dl.head(), 0)

            # this should cause it to notice that it's missing
            dl.pop()
            self.assertEqual(dl.head(), 2)

            # remove the rast of the logs
            for f in glob.glob("testdir/0000*"):
                os.remove(f)
            self.assertEqual(dl.head(), 2)
            dl.pop()
            # head was still in memory
            self.assertEqual(dl.head(), dl.tail())
            self.assertEqual(dl.head(), 9)
        finally:
            shutil.rmtree("testdir")

    def test_disappearing_all(self):
        """Make sure we can hose all of the log files and still make
        progress"""
        try:
            dl = DiskLog("testdir")
            for i in xrange(0, 10):
                dl.append(i)
            dl.sync()
        finally:
            shutil.rmtree("testdir")

        map(os.remove, glob.glob("testdir/000*"))

        try:
            dl = DiskLog("testdir")
            self.assertEqual(dl.head(), None)
            for i in xrange(20, 30):
                dl.append(i)
            dl.sync()
            self.assertEqual(dl.head(), 20)
        finally:
            shutil.rmtree("testdir")

    def test_unwritable_file(self):
        try:
            d = DiskLog("testdir")
            os.chmod(os.path.abspath("testdir"), 0000)
            d.append(1)
            d.append(2)
            d.append(3)

            # we should drop the middle write, because we can't sync
            # to disk.  head and tail are in memory.
            self.assertEqual(d.head(), 1); d.pop()
            self.assertEqual(d.head(), 3)
            
            del d
        except Exception, e:
            print e
        finally:
            os.chmod(os.path.abspath("testdir"), 0755)

        try:
            # the stuff in memory goes away when we reopen the disk
            # log
            d = DiskLog("testdir")
            self.assertEqual(d.head(), None)
        finally:
            shutil.rmtree("testdir")
            
    def test_corrupt_meta(self):
        try:
            d = DiskLog("testdir")
            d.append(1)
            d.close()

            del d
            with open("testdir/META", "w") as fp:
                print >>fp, "CORRUPT"

            d = DiskLog("testdir")
        finally:
            shutil.rmtree("testdir")
