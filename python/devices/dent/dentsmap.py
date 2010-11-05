"""sMAP feed for Dent PowerScout 3 and 18 three-phase Modbus electric
meters.

dent3 and dentconf are example conf files for pointing this daemon at
your dent meters.
"""
import sys
import logging
import time
import threading

sys.path.append('../../newlib')
import SmapHttp
import SmapInstance
import SmapPoint
import smaplog

import dentlib

class DentElement(dict):
    def phase_tree(self):
        return {
            'meter' : {
              'true_energy' : SmapPoint.SmapPoint(None, SmapPoint.Parameter(interval=self.conf.RATE, time='second')),
              'reactive_energy' : SmapPoint.SmapPoint(None, SmapPoint.Parameter(interval=self.conf.RATE, time='second')),
              'apparent_energy' : SmapPoint.SmapPoint(None, SmapPoint.Parameter(interval=self.conf.RATE, time='second')),
              },
            'sensor' : {
              'true_power' : SmapPoint.SmapPoint(None, SmapPoint.Parameter(interval=self.conf.RATE, time='second')),
              'reactive_power' : SmapPoint.SmapPoint(None, SmapPoint.Parameter(interval=self.conf.RATE, time='second')),
              'apparent_power' : SmapPoint.SmapPoint(None, SmapPoint.Parameter(interval=self.conf.RATE, time='second')),
              'displacement_pf' : SmapPoint.SmapPoint(None, SmapPoint.Parameter(interval=self.conf.RATE, time='second')),
              'apparent_pf' : SmapPoint.SmapPoint(None, SmapPoint.Parameter(interval=self.conf.RATE, time='second')),
              'current' : SmapPoint.SmapPoint(None, SmapPoint.Parameter(interval=self.conf.RATE, time='second')),
              'line_frequency' : SmapPoint.SmapPoint(None, SmapPoint.Parameter(interval=self.conf.RATE, time='second')),
              'phase-neutral_voltage' : SmapPoint.SmapPoint(None, SmapPoint.Parameter(interval=self.conf.RATE, time='second')),
              }
            }
    def __init__(self, conf):
        self.conf = conf
        dent_tree = {
            'ABC' : self.phase_tree(),
            'A' : self.phase_tree(),
            'B' : self.phase_tree(),
            'C' : self.phase_tree(),
            'AB' : {
              'sensor' : {
                'volts' : SmapPoint.SmapPoint(None, SmapPoint.Parameter(interval=conf.RATE, time='second')),
                }
              },
            'BC' : {
              'sensor' : {
                'volts' : SmapPoint.SmapPoint(None, SmapPoint.Parameter(interval=conf.RATE, time='second')),
                }
              },
            'AC' : {
              'sensor' : {
                'volts' : SmapPoint.SmapPoint(None, SmapPoint.Parameter(interval=conf.RATE, time='second')),
                }
              }
            }
        
        del dent_tree['ABC']['sensor']['phase-neutral_voltage']
        del dent_tree['A']['sensor']['line_frequency']
        del dent_tree['B']['sensor']['line_frequency']
        del dent_tree['C']['sensor']['line_frequency']
        self.update(dent_tree)

class DentUpdater(threading.Thread):
    def __init__(self, instances, base_conf, conf):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.instances = instances
        self.base_conf = base_conf
        self.conf = conf
        self.updater = dentlib.DentUpdater((base_conf[0], base_conf[1]))

    def run(self):
        while True:
            time_delta = time.time()
            for (inst, addr) in zip(self.instances,
                                    range(self.base_conf[2], len(self.instances)+1)):
                try:
                    self.updater.update(inst, addr)
                except Exception, e:
                    logging.warn("update exception (%s): %s" % (str(addr), str(e)))
                inst.push()

            time_delta = time.time() - time_delta
            time_delta = self.conf.RATE - time_delta
            if time_delta > 0:
                time.sleep(time_delta)

if __name__ == '__main__':
    # import config
    if len(sys.argv) == 2:
        c = __import__(sys.argv[1])
    else:
        c = __import__('dentconf')
        
    if hasattr(c, 'EMAIL'):
        email=c.EMAIL
    else:
        email=None
    smaplog.start_log(emails=email)
    SmapHttp.smap_server_init()

    web_root = {}
    for k,v in c.CONFIG.iteritems():
        web_root[k] = {}
        insts = []
        for elt in ['A','B','C','D','E','F']:
            inst_key = '-'.join(map(str,v)) + '-' + elt
            i = SmapInstance.SmapInstance(DentElement(c), key=inst_key)
            web_root[k]['elt-' + elt] = i
            insts.append(i)
        u = DentUpdater(insts, v, c)
        u.start()
        
    SmapHttp.start_server(web_root, port=c.PORT)
