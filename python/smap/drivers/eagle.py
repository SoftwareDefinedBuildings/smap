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
@author Tyler Hoyt (thoyt@berkeley.edu)
"""
from smap.driver import SmapDriver
from smap.util import periodicSequentialCall

import xml.etree.ElementTree as ET
import socket
import sys
import time

class Eagle(SmapDriver):

    def setup(self, opts):
        self.rate = float(opts.get('rate', 5))
        self.url = opts.get('url')
        self.multiplier = int(opts.get('multiplier', 1))
        xml = self.list_devices()
        root = ET.fromstring(xml)
        self.device = {}
        for child in root:
            self.device[child.tag] = child.text

        self.add_timeseries('/demand', 'kW', data_type="double") 
        self.add_timeseries('/summation_received', 'kWh', data_type="double") 
        self.add_timeseries('/summation_delivered', 'kWh', data_type="double") 
        self.set_metadata('/', 
            { 'Instrument/ModelId': self.device['ModelId'],
              'Instrument/MacId': self.device['DeviceMacId'], 
              'Instrument/Manufacturer': self.device['Manufacturer'] })
            
    def start(self):
        periodicSequentialCall(self.read).start(self.rate)

    def read(self):
        xml = self.get_device_data(self.device['DeviceMacId'])
        # wrap in root element since response aint valid xml!
        xml = "<xml>\n" + xml + "\n</xml>"
        root = ET.fromstring(xml)
        
        # add demand reading
        ID = root.find('InstantaneousDemand')
        try:
            timestamp = int(ID.find('TimeStamp').text, 16)
            demand = int(ID.find('Demand').text, 16)
            dmultiplier = int(ID.find('Multiplier').text, 16)
            ddivisor = int(ID.find('Divisor').text, 16)
            fdemand = 1. * demand * dmultiplier / ddivisor
            fdemand *= self.multiplier
            self.add('/demand', fdemand)
            print 'demand:', fdemand, 'kW'
        except AttributeError:
            pass
       
        # add summation readings
        CS = root.find('CurrentSummation')
        try:
            delivered = int(CS.find('SummationDelivered').text, 16)
            received = int(CS.find('SummationReceived').text, 16)
            smultiplier = int(CS.find('Multiplier').text, 16)
            sdivisor = int(CS.find('Divisor').text, 16)
            fdelivered = 1. * delivered * smultiplier / sdivisor
            freceived = 1. * received * smultiplier / sdivisor
            fdelivered *= self.multiplier
            freceived *= self.multiplier
            self.add('/summation_delivered', fdelivered)
            self.add('/summation_received', freceived)
            print 'delivered:', fdelivered, 'kWh'
            print 'received:', freceived, 'kWh'
        except AttributeError:
            pass

    @staticmethod
    def buffer_response(s):
        rv = ""
        while 1:
            buf = s.recv(1000)
            if not buf:
                break
            rv += buf

        s.close()
        return rv

    def list_devices(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.url, 5002))
        time.sleep(1)

        command = "<LocalCommand>\n <Name>list_devices</Name>\n</LocalCommand>\n"
        s.send(command)

        return self.buffer_response(s)

    def get_device_data(self, mac_id):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.url, 5002))
        time.sleep(1)

        command = '<LocalCommand>\n <Name>get_device_data</Name>\n <MacId>%s</MacId>\n</LocalCommand>\n' % mac_id
        s.send(command)

        return self.buffer_response(s)

if __name__=='__main__':

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Enter your Eagle's IP below
    Eagle_IP = "eagle-000947.local"
    mac_id = "d8d5b9000000129b"

    s.connect((Eagle_IP, 5002))
    time.sleep(1)

    # spaces and LineFeed charachters are important!!!
    sendstr = "<LocalCommand>\n <Name>list_devices</Name>\n</LocalCommand>\n"
    s.send(sendstr)

    print "sending to Eagle: \n\r"
    sys.stdout.write(sendstr)
    time.sleep(1)
    print

    print "Eagle response: \n\r"

    while 1:
        buf = s.recv(1000)
        if not buf:
            break
        sys.stdout.write(buf)

    s.close()
    time.sleep(1)

    print "parse this response and us ethe MACID to request more information\n\r"

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print s

    s.connect((Eagle_IP, 5002))
    time.sleep(1)

    # spaces and LineFeed charachters are important!!!
    sendstr = '<LocalCommand>\n <Name>get_device_data</Name>\n <MacId>0x%s</MacId>\n</LocalCommand>\n' % mac_id
    s.send(sendstr)

    print
    print "sending to Eagle: \n\r"
    sys.stdout.write(sendstr)
    time.sleep(1)

    print
    print "Eagle response: \n\r"

    while 1:
        buf = s.recv(1000)
        if not buf:
            break
        sys.stdout.write(buf)

    time.sleep(1)

    s.close()
