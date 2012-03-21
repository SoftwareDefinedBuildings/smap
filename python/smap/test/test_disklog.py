
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

