#!/usr/bin/env python
# encoding: utf-8
"""
PowerMeter.py

Created by Fred Jiang on 2010-02-18.
Copyright (c) 2010 UC Berkeley. All rights reserved.
"""

import sys
import os
import time
import threading
import rfc3339
import httplib, urllib
import json

import signal
signal.signal(signal.SIGINT, signal.SIG_DFL)


class PowerMeterACme(threading.Thread):
    def __init__(self, SensePoint, Token, Path, Calibration=24, SummationInterval=60, ReportPeriod=15):
        threading.Thread.__init__(self)
        self.SensePoint = SensePoint
        self.SummationInterval = SummationInterval
        self.ReportPeriod = ReportPeriod
        self.Calibration = Calibration
        self.Token = Token
        self.Path = Path
        
    def readPower(self, meter):
        """docstring for readPower"""
        f = urllib.urlopen("http://buzzing.cs.berkeley.edu:8080/data/" + str(meter) + "/meter/0/reading")
        # Read from the object, storing the page's contents in 's'.
        s = f.read()
        f.close()
        j = json.loads(s)
        return [j['SummationDelivered'],j['ReadingTime']]

    def durMeasurement(self,energy,time):
        """Create XML for the durational measurement"""

        msg = \
"""<?xml version="1.0" encoding="UTF-8"?>
<entry xmlns="http://www.w3.org/2005/Atom"
    xmlns:meter="http://schemas.google.com/meter/2008">
    <meter:startTime meter:uncertainty="1.0">""" + rfc3339.rfc3339(time-15*60,1) + """</meter:startTime>
    <meter:endTime meter:uncertainty="1.0">""" + rfc3339.rfc3339(time,1) + """</meter:endTime>
    <meter:quantity meter:uncertainty="0.001" meter:unit="kW h">""" + str(energy) + """</meter:quantity>
</entry>"""
        return msg

    def post(self,msg):
        headers = {"Content-type": "application/atom+xml","Authorization": "AuthSub token=\"" + self.Token + "\""}
        url = self.Path
        # print headers
        # print url
        print msg
        
        conn = httplib.HTTPSConnection("www.google.com")
        conn.request("POST", url, msg, headers)
        response = conn.getresponse()
        print response.status, response.reason
        data = response.read()
        # print data
        conn.close()
        
    def run(self):
        mytime = 0
        myenergy = 0
        period = self.ReportPeriod # 15 minutes
        while 1:
            p,t = self.readPower(self.SensePoint)
            e = p/self.Calibration/self.SummationInterval
            print self.SensePoint,e,t
            myenergy += e
            mytime+=1
            if (mytime == period):
                energykwh = myenergy/period/float(1000) # to get kWh
                # print energykwh
                msg = self.durMeasurement(energykwh,t)
                mytime = 0
                myenergy = 0
                self.post(msg)
            time.sleep(self.SummationInterval)    

def main():
    acmeInfo = [\
        [325,"CIHh4MlGEMP9us8B","/powermeter/feeds/user/14964904574349029689/14964904574349029689/variable/Berkeley.ACmeX2.325.d1/durMeasurement"],\
        [369,"CKL00J-5GBCAx8bIBQ","/powermeter/feeds/user/10895850522346178100/10895850522346178100/variable/Berkeley.ACmeX2.369.d1/durMeasurement"],\
        [350,"CIHh4MlGELWwzI4D","/powermeter/feeds/user/14964904574349029689/14964904574349029689/variable/Berkeley.ACmeX2.350.d1/durMeasurement"]
        ]
        
    acmeThreads = map(lambda x: PowerMeterACme(x[0],x[1],x[2]), acmeInfo)    
    map(lambda x: x.start(), acmeThreads)

    
if __name__ == '__main__':
    main()

