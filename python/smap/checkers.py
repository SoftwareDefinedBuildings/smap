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
properly)
"""

import sys
import urllib2
import time
from twisted.internet import reactor
#set json keywords
(true, false, null) = (True, False, None)

def datacheck(source, driver, first, timep, qurl):
    """This function kills the reactor when the driver's stats feed reports that
    no data is being added."""
    # baseurl needs to eventually be pulled from the ini file for the driver
    baseurl = qurl + "query?"
    query1 = 'select * where Metadata/SourceName = "' 
    query1 = query1 + source 
    query1 = query1 + '" and Path like "/DriverStats/' + driver + '%"'
    result = eval(urllib2.urlopen(baseurl, query1).read())
    uuid = result[0]["uuid"]
    print("checking: " + uuid)

    # now check for data
    # dataurl needs to eventually be pulled from the ini file for the driver
    dataurl = qurl + "data/uuid/"
    endtime = int(time.time()*1000)
    starttime = endtime-(60000*int(timep))
    dataquery = uuid + "?starttime=" + str(starttime) + "&"
    dataquery = dataquery + "endtime=" + str(endtime)
    dq = urllib2.urlopen(dataurl + dataquery)
    resp = eval(dq.readlines()[0])[0]
    dq.close()

    #see if at least one point in user defined time window
    count = len(resp["Readings"])
    if count == 0 and not first:
        print("Driver ERROR")
        reactor.stop()
    elif count == 0 and first:
        print("First driver ERROR, give it time to load")
    return False
