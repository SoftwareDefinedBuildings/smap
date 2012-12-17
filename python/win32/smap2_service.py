"""
Windows service for bacnet_smap2
@author Andrew Krioukov
3/4/12 Initial version
"""
# Twisted uses signals which does not work in windows
def _dummy_signal(*args, **kwargs):
    pass
import os
import sys
import signal
signal.signal = _dummy_signal

from twisted.internet import reactor

import win32service
import win32serviceutil
import win32event
import win32evtlogutil
import win32traceutil
import servicemanager
import traceback

# Must be importated after twisted so that the signal is overwritten
import smap.server
import smap.loader

from smap.drivers import example, quickopc

class smapService(win32serviceutil.ServiceFramework):
  _svc_name_ = "smapService"
  _svc_display_name_ = "sMAP Driver Service"
  _svc_description_ = "Runtime for the sMAP interface drivers"
  _svc_deps_ = ["EventLog"]
  
  def __init__(self, args):
    win32serviceutil.ServiceFramework.__init__(self, args)
    self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)

  def _smap_start(self):
    cfg = os.path.join(os.path.dirname(sys.modules[__name__].__file__), 'smap.ini')
    if not os.path.isfile(cfg):
        cfg = 'smap.ini'
    self.inst = smap.loader.load(cfg)
    smap.server.run(self.inst)

  def SvcStop(self):
    self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
    reactor.callFromThread(reactor.stop)
    win32event.SetEvent(self.hWaitStop)

  def SvcDoRun(self):
    self._smap_start()
    win32event.WaitForSingleObject(self.hWaitStop,win32event.INFINITE)

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(smapService)
