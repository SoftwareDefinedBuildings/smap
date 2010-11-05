
import sys
import os
import threading
import logging
import time
import socket
import ACReport
import re
import MySQLdriver

class ACmeDriver(threading.Thread):
    def __init__(self, SummationInterval=60, InstantaneousInterval=15):
        threading.Thread.__init__(self)
        
        self.routerPrefix = '2001:470:1f04:5b8'
        self.actuatorSock = socket.socket( socket.AF_INET6, socket.SOCK_DGRAM )
        
        self.DBdriver = MySQLdriver.MySQLdriver();
        
        self.logger = logging.getLogger('VerisMeterPoller')
        
        self.summation_interval  = SummationInterval
        # self.instantaneous_interval = InstantaneousInterval
        
        # self.last_summation     = time.time()
        
        self.last_summation = {}
        self.last_capture = time.time()
        
        # self.last_instantaneous = 0
        
        # self.meter = meter
        
        self.instantaneous  = {
            'PowerFactor' : {},
            'Power'       : {},
            'UpdateTime'  : {}
        }
        
        
        # self.metervals = {
        #     'Summation'   : [0.0] * 42
        #     }
        
        self.metervals = {
            'Summation' : {}
        }
        
        self.changeHandler = None
        
        self.host = ''
        self.port = 7001
    
    def addChangeHandler(self, handler):
        self.changeHandler = handler
    
    def setCollect(self, collect, chan_collection):
        self.collect = collect
        self.chan_collection = chan_collection
        
    def actuate(self, moteid, state='on'):
        moteAddr = self.routerPrefix + '::' + hex(moteid)[2:]
        motePort= 2000
        
        message = 'set ' + state
        
        print message, moteAddr, motePort
        
        msg = "echo '" + message + "' | nc6 --send-only -u " + moteAddr + " " + str(motePort)
        print msg
        
        os.system(msg)
        # self.actuatorSock.sendto( message, (moteAddr, motePort) )
        
        
    def run(self):
        while True:
            # conn = MySQLdb.connect (host = "ip",
            #                         user = "username",
            #                         db = "dbname",
            #                         passwd = "pass")
            # cursor = conn.cursor();
            
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.bind((self.host, self.port))
            
            while True:
                data, addr = s.recvfrom(1024)
                if (len(data) > 0):
                    rpt = ACReport.AcReport(data=data, data_length=len(data))
                    myaddr = str(addr[0]).split(":")
                    # print myaddr
                    moteid = int(myaddr[5],16)
            	    power = rpt.get_power();
            	    energy = rpt.get_energy();
            	    maxPower = rpt.get_maxPower();
            	    minPower = rpt.get_minPower();
                    averagePower = rpt.get_averagePower();
                    try:
                        hop_limit = rpt.get_route_hop_limit();
                        parent = rpt.get_route_parent();
                        parent_metric = rpt.get_route_parent_metric();
                        parent_etx = rpt.get_route_parent_etx();
                    except:
                        parent = -1
                        hop_limit = -1
                        parent_metric = -1
                        parent_etx = -1
                    try:
                        totalEnergy = rpt.get_totalEnergy();
                    except:
                        totalEnergy = -1
                    try:
                        seq = rpt.get_seq();
                    except:
                        seq = 0
                    # print "moteid=%d, parent=%d, energy=%ld" % (moteid, parent, energy)
                    
                    # Inserting into DB
                    
                    self.DBdriver.insertDB([moteid,seq,power,averagePower,maxPower,minPower,energy,totalEnergy],\
                             [parent,parent_metric,parent_etx,hop_limit])
                    
                    self.metervals['Summation'][moteid] = energy
                    self.last_summation[moteid] = time.time()
                    self.logger.debug("updated meter values")
                    
                    self.instantaneous['PowerFactor'][moteid] = 1
                    self.instantaneous['Power'][moteid] = power
                    self.instantaneous['UpdateTime'][moteid] = time.time()
                    # self.last_instantaneous = self.instantaneous['UpdateTime']
                    self.logger.debug("updated instantaneous values")
                    
                    if time.time() - self.last_capture > self.summation_interval:
                        if self.changeHandler:
                            self.changeHandler()
                        self.last_capture = time.time()
                        
                    self.collect.resources[str(moteid)] = self.chan_collection
    
    

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    server = sys.argv[1]
    port = int(sys.argv[2])
    
    # v = VerisMeter(server, port)
    # s = VerisMeterPoller(v)
    s = VerisMeterPoller()
    
    s.run()
#     print v.get_power()
#     print v.get_current()
#     v.reset_energy()
#     time.sleep(60)
#     print "energy:", v.get_energy()
