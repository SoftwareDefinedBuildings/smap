"""
Copyright (c) 2013, Regents of the University of California
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

import uuid
import time
import random

from twisted.trial import unittest
from twisted.enterprise import adbapi

from smap import operators, core
from smap.ops import grouping, arithmetic
from smap.ops import util as oputils

import smap.util as util
import psycopg2
import ssmap as ss

class TestRestInterface(unittest.TestCase):

    DB_USER="archiver"
    DB_PASSWD="password"
    DB_NAME="archiver"
    TURL="http://127.0.0.1:8079"
    subkey='8AUYLo3KpQgw5eH1QVu7WuVFunittest9001'
    
    def delete_user(self):
        con = psycopg2.connect("port=5432 host=127.0.0.1 dbname={} user={} password={}".format(self.DB_NAME,self.DB_USER,self.DB_PASSWD))
        cur = con.cursor()
        cur.execute("DELETE FROM stream WHERE subscription_id = (SELECT id FROM subscription WHERE owner_id=9001 LIMIT 1)")
        cur.execute("DELETE FROM subscription WHERE owner_id = 9001")
        cur.execute("DELETE FROM auth_user WHERE id = 9001")
        con.commit()
        cur.close()
        con.close()
        
    def make_user(self):
        """
        Mostly copied from the twisted archiver plugin
        """
        #It's over 9000 so that should be ok.
        uid=9001
        #make a user:
        uqry = """INSERT INTO auth_user VALUES ({id}, 'unittester{id}','','','',
                  'pbkdf2_sha256$10000$QWwLmgl17URJ$cZ258SNnRqER3V1e4HMOMTMyjUZI0fAmlJr/elMLS14=',
                  't','t','t','2013-10-08 22:21:35.566316-07','2013-10-08 22:01:57.650245-07')""".format(id=uid)
        guuid = str(uuid.uuid1())
        #make the connection string
        sqry = """INSERT INTO subscription (uuid, resource, key, public, description, url, owner_id) VALUES ('{uuid}','/+','{subkey}','t','test2','',{uid});"""
        sqry = sqry.format(uid=uid,uuid=guuid,subkey=self.subkey)
        
        #I don't care about async in tests    
        con = psycopg2.connect("port=5432 host=127.0.0.1 dbname={} user={} password={}".format(self.DB_NAME,self.DB_USER,self.DB_PASSWD))
        cur = con.cursor()
        cur.execute(uqry)
        cur.execute(sqry)
        con.commit()
        cur.close()
        con.close()

    
    def setUp(self):
        self.delete_user()
        self.make_user()
        
    def tearDown(self):
        #TODO delete actual streams too
        #self.delete_user()
        pass    

    def mk_data(self, n, start, end):
        step = int(((end-start) / float(n)))
        rv = []
        for i in xrange(n):
            rv.append( (start+i*step, i) )
        return rv
    
    def do_rangetest(self, starttime, endtime, sunit, qunit, n):
        self.assertGreater(starttime, 0, "Zero or negative times don't work nicely")
        s = ss.Ssstream(srcFullName="unittest", url=self.TURL, subkey=self.subkey, unitofTime=sunit)      
        dat = self.mk_data(n, starttime, endtime)
        self.assertEqual(len(dat),n,"Generated data is wrong length")
        s.set_readings(dat)
        
        self.assertTrue(s.publish(), "Failed to publish readings")
        time.sleep(0.3) #Let the archiver calm down a bit and process all dem data
        rv = s.get_readings(starttime*util.time_mult(frm=sunit,to=qunit), 
                            endtime*util.time_mult(frm=sunit,to=qunit), unit=qunit)
        if (len(rv) != n):
            #Instead of false failing for large dataset tests, let us give it a second
            #chance
            time.sleep(2)
            rv = s.get_readings(starttime*util.time_mult(frm=sunit,to=qunit), 
                            endtime*util.time_mult(frm=sunit,to=qunit), unit=qunit)
        self.assertEqual(len(rv),n, "Received data is the wrong length")
        for idx in range(n):
            self.assertEqual(int(dat[idx][0]*util.time_mult(frm=sunit,to=qunit)),
                             rv[idx][0], "Received data timestamp differs from sent data timestamp (after unit conversion)")
            self.assertAlmostEqual(dat[idx][1], rv[idx][1], 2, "Received data value differs significantly from sent data value")
    
    #TODO do a density test of readings 1ns apart in the other one        
    def insert_test_data(self, dat=None):
        if dat is None:
            dat = self.mk_data(1000, 1000, 5000000)
        #TODO test with multiple units as query code is hardcoded
        s = ss.Ssstream(srcFullName="unittest", url=self.TURL, subkey=self.subkey, unitofTime="ms")
        s.set_readings(dat)
        self.assertTrue(s.publish(), "Failed to publish readings")   
        time.sleep(0.5)
        return (dat, s)
    
    def dtest_directget(self):
        dat, s = self.insert_test_data()     
        rv = s.get_readings(0, 6000000)
        self.assertEqual(len(rv),1000)
        
    def dtest_simplequery(self):
        dat, s = self.insert_test_data()
        try:
            rv = s.query("select data after 0 limit 50000 where uuid='{uuid}'")
        except ValueError as e:
            self.fail("Query gave bad HTTP response:",e)
        self.assertEqual(len(rv[0]["Readings"]), 1000)
        
    def dtest_metadata_query(self):
        dat, s = self.insert_test_data()
        rv = s.query("select * where uuid='{uuid}'")
        self.assertEqual(rv[0]["Metadata"]["SourceName"], "unittest")    
        
    def dtest_op_max(self):
        dat, s = self.insert_test_data()
       # print "inserted data is: ",dat
        rv = s.query("apply max to data in (1200,16000) where uuid='{uuid}'")
        print "rv is",rv
        self.assertEqual(rv[0]["Readings"][0][0], 15000)
        self.assertEqual(rv[0]["Readings"][0][1], 3)
        
    def dtest_op_min(self):
        dat, s = self.insert_test_data()
        rv = s.query("apply min to data in (14000,18000) where uuid='{uuid}'")
        print "rv is", rv
        self.assertEqual(rv[0]["Readings"][0][0], 15000)
        self.assertEqual(rv[0]["Readings"][0][1], 3)    
    
    def dtest_tight_median(self):
        _, s = self.insert_test_data(zip(range(1,10),range(40,50)))
        rv = s.query("apply median to data in (0 , 10) limit 100 where uuid='{uuid}'")
        
    def test_median(self):
        _, s = self.insert_test_data(zip(range(1000,10000,1000),range(40,50)))
        rv = s.query("apply median to data in (0 , 10000) limit 100 where uuid='{uuid}'")
        self.assertEqual(len(rv[0]["Readings"]), 1)
        self.assertEqual(len(rv[0]["Readings"][0]), 2)
        self.assertEqual(rv[0]["Readings"][0][1], 44)
   
    def test_mean(self):
        _, s = self.insert_test_data(zip(range(1000,10000,1000),range(50,60)))
        rv = s.query("apply mean to data in (0 , 10000) limit 100 where uuid='{uuid}'")
        self.assertEqual(len(rv[0]["Readings"]), 1)
        self.assertEqual(len(rv[0]["Readings"][0]), 2)
        self.assertEqual(rv[0]["Readings"][0][1], 54)    
    
    def test_sum(self):
        _, s = self.insert_test_data(zip(range(1000,10000,1000),range(50,60)))
        rv = s.query("apply sum to data in (0 , 11000) limit 100 where uuid='{uuid}'")
        self.assertEqual(len(rv[0]["Readings"]), 1)
        self.assertEqual(len(rv[0]["Readings"][0]), 2)
        self.assertEqual(rv[0]["Readings"][0][1], 486)
            
    def test_fail_sum(self):
        _, s = self.insert_test_data(list(zip(range(1000,10000,1000),range(50,60))) + [(10000, float('nan'))])
        rv = s.query("apply sum to data in (0 , 11000) limit 100 where uuid='{uuid}'")
        self.assertEqual(len(rv[0]["Readings"]), 1)
        self.assertEqual(len(rv[0]["Readings"][0]), 2)
        #NaN causes None to appear
        self.assertEqual(rv[0]["Readings"][0][1], None)
              
    def test_nansum(self):
        _, s = self.insert_test_data(list(zip(range(1000,10000,1000),range(50,60))) + [(10000, float('nan'))])
        rv = s.query("apply nansum to data in (0 , 11000) limit 100 where uuid='{uuid}'")
        self.assertEqual(len(rv[0]["Readings"]), 1)
        self.assertEqual(len(rv[0]["Readings"][0]), 2)
        #NaNs should be zero
        self.assertEqual(rv[0]["Readings"][0][1], 486) 
    
    def test_variance(self):
        _, s = self.insert_test_data(zip(range(1000,11000,1000), [4, 5, 0, 4, 5, 1, 6, 1, 8, 4]))
        rv = s.query("apply var to data in (0 , 11000) limit 100 where uuid='{uuid}'")
        self.assertEqual(len(rv[0]["Readings"]), 1)
        self.assertEqual(len(rv[0]["Readings"][0]), 2)
        self.assertAlmostEqual(rv[0]["Readings"][0][1], 5.56)
        
    def test_std(self):
        _, s = self.insert_test_data(zip(range(1000,11000,1000), [4, 5, 0, 4, 5, 1, 6, 1, 8, 4]))
        rv = s.query("apply std to data in (0 , 11000) limit 100 where uuid='{uuid}'")
        #rv = s.query("select data in (0 , 11000) limit 100 where uuid='{uuid}'")
        #print rv[0]["Readings"]
        self.assertEqual(len(rv[0]["Readings"]), 1)
        self.assertEqual(len(rv[0]["Readings"][0]), 2)
        self.assertAlmostEqual(rv[0]["Readings"][0][1], 2.3579652245103193)    
    
    def test_prod(self):
        _, s = self.insert_test_data(zip(range(1000,11000,1000), [4, 5, 3, 4, 5, 1, 6, 1, 8, 4]))
        rv = s.query("apply prod to data in (0 , 11000) limit 100 where uuid='{uuid}'")
        #rv = s.query("select data in (0 , 11000) limit 100 where uuid='{uuid}'")
        #print rv[0]["Readings"]
        self.assertEqual(len(rv[0]["Readings"]), 1)
        self.assertEqual(len(rv[0]["Readings"][0]), 2)
        self.assertEqual(rv[0]["Readings"][0][1], 230400)
        
    def test_nanmean(self):
        _, s = self.insert_test_data(list(zip(range(1000,10000,1000),range(50,60))) + [(10000, float('nan'))])
        rv = s.query("apply nanmean to data in (0 , 11000) limit 100 where uuid='{uuid}'")
        self.assertEqual(len(rv[0]["Readings"]), 1)
        self.assertEqual(len(rv[0]["Readings"][0]), 2)
        #NaNs should be zero
        self.assertEqual(rv[0]["Readings"][0][1], 54)     
   
    def test_add_c(self):
        dat, s = self.insert_test_data(zip(range(1000,11000,1000), [4, 5, 3, 4, 5, 1, 6, 1, 8, 4]))     
        rv = s.query("apply add (2) to data in (0 , 11000) limit 100 where uuid='{uuid}'")
        self.assertEqual(len(rv[0]["Readings"]), 10)
        for i in range(10):
            self.assertEqual(rv[0]["Readings"][i][0], dat[i][0])
            self.assertEqual(rv[0]["Readings"][i][1], dat[i][1]+2)
 
        
        
        
            
