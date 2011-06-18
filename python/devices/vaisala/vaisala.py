"""sMAP source for Vaisala WXT520 weather station running in automatic
ASCII mode.

@author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
"""

import sys
import socket
import threading
import time
import logging

sys.path.append("../../newlib")
import smaplog
import SmapInstance
import SmapHttp
import SmapPoint
import util

import conf

VAISALA_UNITS = {
    'R1' : {
      'D' : 'deg',
      'M' : 'm/s',
      },
    'R2' : {
      'C' : 'C',
      'P' : 'rh',
      'H' : 'Pa',
      },
    'R3' : {
      'M' : 'mm',
      's' : 'second',
      }
    }

VAISALA_POINTS = {
    'R1' : (
       'wind', {
         'direction' : ('Dm', 'Dn', 'Dx'),
         'speed' : ('Sm', 'Sn', 'Sx')
         }
       ),
    'R2' : (
       'pth', {
         'temperature' : ('Ta', None, None),
         'rh' : ('Ua', None, None),
         'pressure' : ('Pa', None, None),
         }
       ),
    'R3' : (
       'precipitation', {
          'rain_accumulation' : ('Rc', None, None),
          'rain_duration' : ('Rd', None, None),
          'rain_intensity' : ('Ri', None, 'Rp'),
          'hail_accumulation' : ('Hc', None, None),
          'hail_duration' : ('Hd', None, None),
          'hail_intensity' : ('Hi', None, 'Hp')
          }
       )
    }    

class VaisalaReader(threading.Thread):
    def __init__(self, netloc, inst):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.netloc = netloc
        self.inst = inst
        self.log = logging.getLogger('VaisalaReader')

    def run(self):
        self.log.info("Up, reading from " + str(self.netloc))
        sock = util.socket_readline(socket.AF_INET, socket.SOCK_STREAM, 0)
        sock.settimeout(10)
        sock.connect(self.netloc)
        while True:
            line = sock.readline()
            self.log.debug("Read: " + line)
            fields = line.split(',')
            reg = fields[0][1:]
            def proc_field(f):
                v = f.split('=')
                return (v[0], (v[1][:-1], v[1][-1]))
            data = dict(map(proc_field, fields[1:]))

            if VAISALA_POINTS.has_key(reg):
                point = VAISALA_POINTS[reg][0]
                # create the point in the smap tree
                if not self.inst['data'].has_key(point):
                    self.log.info("Creating sMAP points for " + point)
                    self.inst['data'][point] = {'sensor' : {}, 'meter' : {}}
                    for k,v in VAISALA_POINTS[reg][1].iteritems():
                        unit = VAISALA_UNITS[reg][data[v[0]][1]]
                        self.inst['data'][point]['sensor'][k] = SmapPoint.SmapPoint(SmapPoint.Formatting(unit=unit, multiplier=None,
                                                                                                         divisor=None,type='air',
                                                                                                         ctype='sensor'),
                                                                                    SmapPoint.Parameter(interval=-1, time='second'))
                for k,v in VAISALA_POINTS[reg][1].iteritems():
                    val_ = data.get(v[0])[0]
                    min_ = data.get(v[1], None)
                    if min_ != None: min_ = min_[0]
                    max_ = data.get(v[2], None)
                    if max_ != None: max_ = max_[0]
                    self.inst['data'][point]['sensor'][k].add(SmapPoint.Reading(time=time.time(),
                                                                                value=val_,
                                                                                min=min_,
                                                                                max=max_))
                self.inst.push(dirty_path='~/data/' + point)

if __name__ == '__main__':
    smaplog.start_log()
    SmapHttp.smap_server_init()

    root = {}
    for k,v in conf.CONF.iteritems():
        root[k] = SmapInstance.SmapInstance({}, key='vaisala-' + v[0] + '_' + str(v[1]))
        r = VaisalaReader(v, root[k])
        r.start()
        
    SmapHttp.start_server(root, port=conf.PORT)
