
import sys
import logging
import time
import signal
import pickle

signal.signal(signal.SIGINT, signal.SIG_DFL)
sys.path.append('../../newlib')

import SmapHttp
import SmapInstance
import SmapPoint
import smaplog

import ClimateX2Report as ClimateReport
import socket
import re
import MySQLdb as sql
import time

import grizzled.os

host = ''
port = 7001

if __name__ == '__main__':
    smaplog.start_log()

    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.bind((host, port))

    conn = sql.connect (host = "localhost",
        user = "jay",
        db = "cory",
        passwd = "410soda")

    inst = SmapInstance.SmapInstance({}, key="ClimateSmap")
    SmapHttp.start_server(inst,background=True)

#    grizzled.os.daemonize()

    while True:
        data, addr = s.recvfrom(1024)
#        if (len(data) > 0):
        if (len(data) == 37):
            print time.strftime("%Y-%m-%d %H:%M:%S"), len(data), [ord(x) for x in data]
            rpt = ClimateReport.ClimateReport(data=data, data_length=len(data))

            origin = int(addr[0].split(':')[-1], 16)

            if not inst['data'].has_key(str(origin)):
                data = {
                    'sensor' : {'room_temp' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='C',multiplier=None,divisor=None,type='air',ctype='sensor'),SmapPoint.Parameter(interval=10, time='second')),
                                'room_hum' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='rh',multiplier=None,divisor=None,type='air',ctype='sensor'),SmapPoint.Parameter(interval=10, time='second')),
                                            } }

                inst['data'][str(origin)] = data

            print addr
            print rpt
            print

            for idx in range(0,2):
                insert = """INSERT INTO climate199 VALUES (%i, %i, UNIX_TIMESTAMP(), %i, %i, %i, %i, %i);""" % (
                    int(addr[0].split(':')[-1], 16),
                    rpt.get_seq(),
                    rpt.get_localTime(),
                    rpt.get_globalTime() - (rpt.get_period() * (1 - idx)),
                    rpt.get_period(),
                    rpt.get_readings_temp()[idx],
                    rpt.get_readings_hum()[idx])
                          
                try:
                    cursor = conn.cursor()
                    cursor.execute(insert)
                except:
                    print "EXCEPTION"

                new_time = rpt.get_globalTime() - (rpt.get_period() * (1 - idx))
                new_temp = (rpt.get_readings_temp()[idx] * 0.98 - 3840.0) / 100.0
                if (new_temp > 100):
                    new_temp = 100
                elif (new_temp < -40):
                    new_temp = -40

                converted_hum = 0.0405 * rpt.get_readings_hum()[idx] - 4 - rpt.get_readings_hum()[idx] * rpt.get_readings_hum()[idx] * 0.0000028
                new_hum = (new_temp - 25.000) * (0.0100 + 0.00128 * converted_hum) + converted_hum;
                if (new_hum > 100):
                    new_hum = 100.00;
                elif (new_hum < 0):
                    new_hum = 0.00;

                inst['data'][str(origin)]['sensor']['room_temp'].add(SmapPoint.Reading(time=new_time,value=new_temp,min=None,max=None))
                inst['data'][str(origin)]['sensor']['room_hum'].add(SmapPoint.Reading(time=new_time,value=new_hum,min=None,max=None))
                inst.push(dirty_path='~/data/'+str(origin))

            conn.commit()
        else:
	    print "Received packed of wrong length (%d != 37). Skipping." % len(data)
