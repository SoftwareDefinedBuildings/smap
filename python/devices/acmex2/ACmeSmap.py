
import sys
import os
import threading
import logging
import time
import socket


sys.path.append("../../newlib")

import smaplog
import SmapInstance
import SmapPoint
import SmapHttp

import conf
import ACmeX2Report
import MysqlListener

def get_acme_tree():
    return {
        'sensor' : {
            'true_power' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='kW', multipler=None,
                                                                    divisor=1e6, type='electric',
                                                                    ctype='sensor'),
                                               SmapPoint.Parameter(interval=10, time='second')),
            'apparent_power' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='kVA', multipler=None,
                                                                        divisor=1e6, type='electric',
                                                                        ctype='sensor'),
                                                   SmapPoint.Parameter(interval=10, time='second'))
            },
        'meter' : {
            'true_energy' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='kWh', multipler=None,
                                                                     divisor=1e6, type='electric',
                                                                     ctype='sensor'),
                                                SmapPoint.Parameter(interval=10, time='second'))
            }
        }

class ACmeListener(threading.Thread):
    def __init__(self, inst, acmeport=7001):
        threading.Thread.__init__(self)
        self.inst = inst
        self.acmeport = acmeport
        self.daemon = True

    def run(self):
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        # listener = MysqlListener.Listener()
        log = logging.getLogger('ACmeListener')
        sock.bind(('', self.acmeport))
        while True:
            data, addr = sock.recvfrom(1024)
            rpt = ACmeX2Report.AcReport(data=data, data_length=len(data))
            print rpt

            # listener.recv(data, addr)
            mid = "%i" % (int(addr[0].strip().split(':')[-1], 16))

            if not self.inst['data'].has_key(mid):
                self.inst['data'][mid] = get_acme_tree()

#             meter.metering_interval = rpt.get_period()
#             meter.sensing_interval = rpt.get_period()
#             meter.parameters['UniqueId'] = ':'.join(['%02x' % x for x in rpt.get_eui64()])

            for idx in range(0,2):
                readingTime = rpt.get_globalTime() - (rpt.get_period() * (1 - idx))
                self.inst['data'][mid]['meter']['true_energy'].add(
                    SmapPoint.Reading(time=readingTime,
                                      value=rpt.get_readings_cumulativeRealEnergy()[idx],
                                      min=None, max=None))
                self.inst['data'][mid]['sensor']['true_power'].add(
                    SmapPoint.Reading(time=readingTime,
                                      value=rpt.get_readings_averageRealPower()[idx],
                                      min=None, max=None))
                self.inst['data'][mid]['sensor'].add(
                    SmapPoint.Reading(time=readingTime,
                                      value=rpt.get_readings_averageApparentPower()[idx],
                                      min=None, max=None))
                self.inst.push(dirty_path='~/data/' + mid)

if __name__ == '__main__':
    smaplog.start_log()

    inst = SmapInstance.SmapInstance({}, key='acmex2-smap-%i' % conf.PORT)
    updater = ACmeListener(inst)
    updater.start()

    SmapHttp.start_server(inst, port=conf.PORT)
    
