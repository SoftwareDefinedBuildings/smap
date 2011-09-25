
import sys
import time
import datetime

from twisted.internet import reactor, defer
from twisted.python import log

from smap import loader
from smap.drivers.obvius import bmo
from smap.contrib import dtutil

# day to start import at
startdt = dtutil.strptime_tz("09 01 2011", "%m %d %Y")
enddt = startdt + datetime.timedelta(days=1)
# number of days to request
days = 3

def next_day():
    global startdt
    global enddt
    global inst
    global days

    print "\n\nSTARTING DAY (%i remaining)\n" % days
    tasks = []
    for d in inst.drivers.itervalues():
        if isinstance(d, bmo.BMOLoader):
            tasks.append(d.update(startdt, enddt))

    startdt = startdt + datetime.timedelta(days=1)
    enddt = startdt + datetime.timedelta(days=1)
    d = defer.DeferredList(tasks)
    d.addCallback(lambda _: inst._flush())
    return d

def do_next_day(*args):
    global days
    if days > 0:
        days -= 1
        d = next_day()
        d.addCallback(do_next_day)
        return d
    else:
        pass
    #reactor.stop()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "\n\t%s <conf>\n" % sys.argv[0]

    log.startLogging(sys.stdout)

    inst = loader.load(sys.argv[1])
    do_next_day()
    reactor.run()
