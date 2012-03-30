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

