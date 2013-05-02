"""Example code plotting one day's worth of outside air time-series.

@author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
"""

from smap.archiver.client import SmapClient
from smap.contrib import dtutil

from matplotlib import pyplot
from matplotlib import dates

# make a client
c = SmapClient("http://www.openbms.org/backend")

# start and end values are Unix timestamps
start = dtutil.dt2ts(dtutil.strptime_tz("3-1-2013", "%m-%d-%Y"))
end   = dtutil.dt2ts(dtutil.strptime_tz("3-2-2013", "%m-%d-%Y"))

# hard-code the UUIDs we want to download
oat = [
  "395005af-a42c-587f-9c46-860f3061ef0d", 
  "9f091650-3973-5abd-b154-cee055714e59", 
  "5d8f73d5-0596-5932-b92e-b80f030a3bf7", 
  "ec2b82c2-aa68-50ad-8710-12ee8ca63ca7", 
  "d64e8d73-f0e9-5927-bbeb-8d45ab927ca5"
]

# perform the download
data = c.data_uuid(oat, start, end)

# plot all the data
#  use the epoch2num to convert to pylab date formats
for d in data:
  pyplot.plot_date(dates.epoch2num(d[:, 0] / 1000), d[:, 1], '-',
                   tz='America/Los_Angeles')

pyplot.show()
