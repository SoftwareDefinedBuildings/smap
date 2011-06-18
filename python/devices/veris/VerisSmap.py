"""sMAP gateway for the Veris E30 panel meter connected to a
modbus-ethernet adaptor.

Edit conf.py to point to the IP address and configuration of your
modbus-ethernet adaptor to poll.
"""
import sys
import logging
import time
import pickle
import threading
sys.path.append('../../newlib')

import SmapHttp
import SmapInstance
import SmapPoint
import smaplog
import util

import VerisMeter
import conf


RATE=30

def update_field(smap, type_, field, data, mi=None, ma=None):
    when = int(time.time())
    for i in range(1, 43):
        if i > len(data): return
        smap['data'][str(i)][type_][field].add(SmapPoint.Reading(time=when,
                                                                 value=data[i-1],
                                                                 min=None, max=None))

def update(veris, smap):
    try:
        logging.debug("Updating meter readings")
        current = veris.get_current()
        update_field(smap, 'sensor', 'current', current)
        pf = veris.get_powerfactor()
        update_field(smap, 'sensor', 'pf', pf)
        power = veris.get_power()
        update_field(smap, 'sensor', 'power', power)
        energy = veris.get_energy()
        update_field(smap, 'meter', 'energy', energy)
    except Exception, e:
        logging.error("Exception updating readings: " + str(e))
    finally:
        smap.push()
    

def veris_point():
    return {'sensor' : {
        'pf' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='pf',
                                                        multiplier=None,divisor=None,
                                                        type='electric',ctype='sensor'),
                                   SmapPoint.Parameter(interval=RATE, time='second')),
        'power' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='kW',
                                                           multiplier=None,divisor=None,
                                                           type='electric',ctype='sensor'),
                                      SmapPoint.Parameter(interval=RATE, time='second')),
        'current' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='A',
                                                             multiplier=None,divisor=None,
                                                             type='electric',ctype='sensor'),
                                      SmapPoint.Parameter(interval=RATE, time='second')),
        },
            'meter' : {
        'energy' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='kWh',
                                                            multiplier=None,divisor=None,
                                                            type='electric',ctype='sensor'),
                                       SmapPoint.Parameter(interval=RATE, time='second')),
        }
            }

if __name__ == '__main__':
    v = VerisMeter.VerisMeter(conf.CONF['HOST'], 
                              conf.CONF['PORT'], 
                              conf.CONF['BUS_ADDR'])
    web_root = {}
    for channel in range(1,43):
        web_root[str(channel)] = veris_point()

    inst = SmapInstance.SmapInstance(web_root, key='veris')
    u = util.RateTimer(RATE, lambda: update(v, inst))
    u.start()

    SmapHttp.start_server(inst, port=conf.SMAP_PORT)
