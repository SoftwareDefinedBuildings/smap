#!/usr/bin/python
"""Check to see if a driver is functioning properly, else exit with a non-zero
exit code"""

import sys
from optparse import OptionParser
import urllib2
import time

#set json keywords
(true,false,null) = (True, False, None)

parser = OptionParser()
parser.add_option("-s", "--source", dest="source", help="SourceName Tag", 
                                                    metavar = "SOURCE")
parser.add_option("-d", "--driver", dest="driver", help="Driver Name", 
                                                    metavar = "DRIVER")
parser.add_option("-t", "--timep", dest="timep", help="Time to let pass before"
                  " non-zero exit status reported", metavar = "TIMEP")
(options, args) = parser.parse_args()
source, driver, timep = options.source, options.driver, options.timep

if not source or not driver or not timep:
    print("Insufficient Arguments, see help")
    sys.exit(2)

# baseurl needs to eventually be pulled from the ini file for the driver
baseurl = "http://localhost/backend/api/query?"
query1 = 'select * where Metadata/SourceName = "' 
query1 = query1 + source 
query1 = query1 + '" and Path like "/DriverStats/' + driver + '%"'
result = eval(urllib2.urlopen(baseurl, query1).read())
uuid = result[0]["uuid"]
print("checking: " + uuid)

# now check for data
# dataurl needs to eventually be pulled from the ini file for the driver
dataurl = "http://localhost/backend/api/data/uuid/"
endtime = int(time.time()*1000)
starttime = endtime-(60000*int(timep))
dataquery = uuid + "?starttime=" + str(starttime) + "&endtime=" + str(endtime)
dq = urllib2.urlopen(dataurl + dataquery)
resp = eval(dq.readlines()[0])[0]
dq.close()

#see if at least one point in user defined time window
count = len(resp["Readings"])
if count == 0:
    print("Driver ERROR")
    sys.exit(1)
else:
    print("Driver Running")
    sys.exit(0)
