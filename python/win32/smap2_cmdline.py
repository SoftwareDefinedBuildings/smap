

# Twisted uses signals which does not work in windows
def _dummy_signal(*args, **kwargs):
    pass
import os
import sys
import signal
signal.signal = _dummy_signal

from twisted.internet import reactor

# Must be importated after twisted so that the signal is overwritten
import smap.server
import smap.loader

from smap.drivers import example, quickopc

if __name__ == '__main__':
    cfg = 'smap.ini'
    inst = smap.loader.load(cfg)
    smap.server.run(inst)
