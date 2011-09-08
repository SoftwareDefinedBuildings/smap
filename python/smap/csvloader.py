
# this is the twisted event loop
from twisted.internet import reactor

# use this to get a smap source in one line
import loader

# autoflush means that we don't call flush on a timer
s = loader.load('default.ini', autoflush=None)


CHUNKSIZE=1000
i = 0
def fail(err):
    print "Received error while delivering reports"
    reactor.stop()
    
def do_add(*args):
    global i
    global CHUNKSIZE
    if i > 10000:
        reactor.stop()
    else:
        # publish a bunch of data
        for v in xrange(i*CHUNKSIZE, i*CHUNKSIZE+CHUNKSIZE):
            s.get_timeseries('/sensor0')._add(0, v)
        i += 1
        print "flush", CHUNKSIZE
        
        # then flush. we'll get a callback once we've sent it to all
        # of the destinations
        d = s.reports._flush()
        d.addCallback(do_add)
        d.addErrback(fail)

reactor.callFromThread(do_add)
reactor.run()
