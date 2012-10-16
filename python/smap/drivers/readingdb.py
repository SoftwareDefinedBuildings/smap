
import sys
import logging
import time
import threading
import socket
import json

sys.path.append("../../newlib")
from SmapPoint import SmapPoint, Formatting, Parameter, Reading
import SmapHttp
import SmapInstance
import smaplog
RATE=5

class UpdateThread(threading.Thread):
    def __init__(self, inst, leaf, port, rate=5):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.inst = inst
        self.leaf = leaf
        self.port = port
        self.rate = rate

        self.data = {}
        self.last = time.time()

    def update(self, new):
        timestamp = new['timestamp']
        del new['timestamp']
        for k,v in new.iteritems():
            self.data[k] = self.data.get(k, 0) + v
        if timestamp > self.last + self.rate:
            print "publishing", self.data
            for k, v in self.data.iteritems():
                if self.leaf.has_key(k):
                    self.leaf[k].add(Reading(time=timestamp,value=v,min=None,max=None))
            self.inst.push()
            self.data = {}
            self.last = timestamp

    def run(self):
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, 0)
        s.bind(("::1", self.port))
        while True:
            stats = s.recv(1024)
            data = json.loads(stats)
            self.update(data)

def get_tree(key):
    return  {
        key : {
            'sensor' : {
                'queries' : SmapPoint(Formatting(unit="count", multiplier=None, divisor=RATE,
                                                 type="statistic", ctype="sensor"),
                                      Parameter(interval=1, time='second')),
                'adds' : SmapPoint(Formatting(unit="count", multiplier=None, divisor=RATE,
                                                 type="statistic", ctype="sensor"),
                                      Parameter(interval=1, time='second')),
                'failed_adds': SmapPoint(Formatting(unit="count", multiplier=None, divisor=RATE,
                                                 type="statistic", ctype="sensor"),
                                      Parameter(interval=1, time='second')),
                'connects' : SmapPoint(Formatting(unit="count", multiplier=None, divisor=RATE,
                                                 type="statistic", ctype="sensor"),
                                       Parameter(interval=1, time='second')),
                'disconnects' : SmapPoint(Formatting(unit="count", multiplier=None, divisor=RATE,
                                                 type="statistic", ctype="sensor"),
                                      Parameter(interval=1, time='second')),
                'nearest' : SmapPoint(Formatting(unit="count", multiplier=None, divisor=RATE,
                                                 type="statistic", ctype="sensor"),
                                      Parameter(interval=1, time='second'))
                }
            }
        }

if __name__ == '__main__':
    smaplog.start_log()

    host, port = "jackalope", 4246
    key = "%s_%i" % (host, port)
    port = 4242
    tree = get_tree(key)
    inst = SmapInstance.SmapInstance(tree, key="readingdb")
    u = UpdateThread(inst, inst['data'][key]['sensor'], port)
    u.start()

    SmapHttp.start_server(inst, port=7012)
