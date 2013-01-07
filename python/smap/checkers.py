"""
Copyright (c) 2011, 2012, Regents of the University of California
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions 
are met:

 - Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
 - Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the
   distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL 
THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED 
OF THE POSSIBILITY OF SUCH DAMAGE.
"""
"""
@author Sagar Karandikar <skarandikar@berkeley.edu>
"""
"""A set of checking functions that cause an instance to terminate on different 
failure conditions (at which point monit restarts the instance when configured
properly). A usable checking function has a wrapper that can generate a
no-arg version for use in the instance.
"""

import sys
import time

from twisted.internet import reactor
from twisted.python import log

def datacheck(instance, driver, timep):
    """This function kills the reactor when the instance/driver stats feed 
    reports that no data is being added.
    ARGS: 
    instance - to get points/s
    driver - what to check for, 
    timep - width of allowable window (allowable window is now-(timep seconds)
    """
    # see if at least latest point in user defined time window
    lastpointtime = driver.statslog.latest()
    comparetime = time.time() - timep
    if lastpointtime >= comparetime:
        return
    else:
        log.err("Killing sMAP: no data check violated for driver " + 
                str(driver))
        reactor.stop()

def get(inst, driver, opts):
    if not ('DatacheckWindow' in opts or
            'DatacheckInterval' in opts):
        return None
    else:
        checkwin = int(opts.get('DatacheckWindow', 300))
        checkint = int(opts.get('DatacheckInterval', 300))
        return checkint, datacheckwrap(inst, driver, checkwin)

def datacheckwrap(instance, driver, timep):
    """A wrapper that generates a no-args version of datacheck"""
    return lambda: datacheck(instance, driver, timep)
