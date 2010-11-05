
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

import UdpReport
import socket
import re
import MySQLdb as sql
import time

import grizzled.os

host = ''
port = 7002

if __name__ == '__main__':
    smaplog.start_log()

    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.bind((host, port))

    conn = sql.connect (host = "localhost",
        user = "jay",
        db = "cory",
        passwd = "410soda")

    inst = SmapInstance.SmapInstance({}, key="HydrowatchSmap")
    SmapHttp.start_server(inst,background=True,port=8081)

#    grizzled.os.daemonize()

    methods = []
    insert = "INSERT IGNORE INTO coryroof (unixtimeRecv, origin, "

    re = re.compile('^get_(.*)')
    for method in dir(UdpReport.UdpReport):
        result = re.search(method)
        if result != None:
            insert += str(result.group(1)) + ", "
            methods.append(str(result.group(1)))

    insert = insert[0:len(insert) - 2]
    insert += ") VALUES ("

    while True:
        data, addr = s.recvfrom(1024)
        if (len(data) != 60):
            print time.strftime("%Y-%m-%d %H:%M:%S"), len(data), [ord(x) for x in data]
            rpt = UdpReport.UdpReport(data=data, data_length=len(data))

            origin = int(addr[0].split(':')[-1], 16)

            if not inst['data'].has_key(str(origin)):
                data = {
                    'sensor' : {'roof_temp' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='C',multiplier=None,divisor=None,type='air',ctype='sensor'),SmapPoint.Parameter(interval=300, time='second')),
                                'roof_hum' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='rh',multiplier=None,divisor=None,type='air',ctype='sensor'),SmapPoint.Parameter(interval=300, time='second')),
                                'roof_tsr' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='lx',multiplier=None,divisor=None,type='air',ctype='sensor'),SmapPoint.Parameter(interval=300, time='second')),
                                'roof_par' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='lx',multiplier=None,divisor=None,type='air',ctype='sensor'),SmapPoint.Parameter(interval=300, time='second')),
                                'battvol' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='V',multiplier=None,divisor=None,type='battery',ctype='sensor'),SmapPoint.Parameter(interval=300, time='second')),
                                'solarvol' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='V',multiplier=None,divisor=None,type='PV panel',ctype='sensor'),SmapPoint.Parameter(interval=300, time='second')),
                                'solarcur' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='mA',multiplier=None,divisor=None,type='PV panel',ctype='sensor'),SmapPoint.Parameter(interval=300, time='second')),
                                'intvol' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='V',multiplier=None,divisor=None,type='MCU',ctype='sensor'),SmapPoint.Parameter(interval=300, time='second')),
                                'ecount' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='mA',multiplier=None,divisor=None,type='mote',ctype='sensor'),SmapPoint.Parameter(interval=300, time='second')),
                                            } }

                inst['data'][str(origin)] = data

            filetime  = time.strftime("%Y-%m-%d")

            print

            print addr
            print rpt

            thisInsert = insert
            thisInsert += time.strftime("%s") + ", "
            thisInsert += "0x" + str(origin) + ", "            

            for m in methods:
                try:
                    getter = getattr(rpt, 'get_' + m, None)
                    val = getter()
                except:
                    val = 0
                if (isinstance(val, list)):
                    val = val[0]
                thisInsert += str(val) + ", "
            thisInsert = thisInsert[0:len(thisInsert) - 2]
            thisInsert += ");"

            insert2local = "echo \"" + thisInsert + "\" >> ./HydroTmp/" + filetime

            try:
                print thisInsert
                cursor = conn.cursor()
                cursor.execute(thisInsert)
            except:
                print "EXCEPTION"

#            subprocess.os.system(insert2local)

            new_time = rpt.get_unixTime()
            new_temp = (rpt.get_temp() * 0.98 - 3840.0) / 100.0
            if (new_temp > 100):
				new_temp = 100
            elif (new_temp < -40):
				new_temp = -40

            converted_hum = 0.0405 * rpt.get_hum() - 4 - rpt.get_hum() * rpt.get_hum() * 0.0000028
            new_hum = (new_temp - 25.000) * (0.0100 + 0.00128 * converted_hum) + converted_hum;
            if (new_hum > 100):
				new_hum = 100.00;
            elif (new_hum < 0):
				new_hum = 0.00;

            new_battvol = (rpt.get_battvol() / 4096.0) * 3.29
            new_solarvol = (rpt.get_solarvol() / 4096.0) * 3.29
            new_solarcur = rpt.get_solarcur() * 0.0296
            new_intvol = (rpt.get_intvol() / 4096.0) * 3.29
            new_ecount = ((rpt.get_ecount() * 0.4) / rpt.get_senseRate()) / new_intvol / 1000.0

            inst['data'][str(origin)]['sensor']['roof_temp'].add(SmapPoint.Reading(time=new_time,value=new_temp,min=None,max=None))
            inst['data'][str(origin)]['sensor']['roof_hum'].add(SmapPoint.Reading(time=new_time,value=new_hum,min=None,max=None))
            inst['data'][str(origin)]['sensor']['roof_tsr'].add(SmapPoint.Reading(time=new_time,value=rpt.get_tsr(),min=None,max=None))
            inst['data'][str(origin)]['sensor']['roof_par'].add(SmapPoint.Reading(time=new_time,value=rpt.get_par(),min=None,max=None))
            inst['data'][str(origin)]['sensor']['battvol'].add(SmapPoint.Reading(time=new_time,value=new_battvol,min=None,max=None))
            inst['data'][str(origin)]['sensor']['solarvol'].add(SmapPoint.Reading(time=new_time,value=new_solarvol,min=None,max=None))
            inst['data'][str(origin)]['sensor']['solarcur'].add(SmapPoint.Reading(time=new_time,value=new_solarcur,min=None,max=None))
            inst['data'][str(origin)]['sensor']['intvol'].add(SmapPoint.Reading(time=new_time,value=new_intvol,min=None,max=None))
            inst['data'][str(origin)]['sensor']['ecount'].add(SmapPoint.Reading(time=new_time,value=new_ecount,min=None,max=None))
            inst.push(dirty_path='~/data/'+str(origin))

            conn.commit()
        else:
            print "Received packet of wrong length (%d != 60). Skipping." % len(data)	

