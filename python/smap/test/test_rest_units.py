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
        self.delete_user()
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
            
    def test_simple(self):
        self.do_rangetest(100,10000,"s","s",100)
        
    def test_tconv_s_ms(self):
        self.do_rangetest(100,10000,"s","ms",1000)
          
    def test_tconv_ns_ms(self):
        start=1382136027832092160
        end = start + 10*24*60*60*1000*1000*1000
        self.do_rangetest(start,end,"ns","ms",5000)  
        
    def test_tconv_ns_ns(self):
        start=1382136027832092160
        end = start + 10*24*60*60*1000*1000*1000
        self.do_rangetest(start,end,"ns","ns",5000)          
        
    def test_tconv_ns_s(self):
        start=1382136027832092160
        end = start + 10*24*60*60*1000*1000*1000
        self.do_rangetest(start,end,"ns","s",5000)        
    

