"""Example code plotting one day's worth of outside air time-series,
locating the streams using a metadata query.

@author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
"""

from smap.archiver.client import SmapClient
from smap.contrib import dtutil
from matplotlib import pyplot

# make a client
c = SmapClient("http://www.openbms.org/backend")

# start and end values are Unix timestamps
start = dtutil.dt2ts(dtutil.strptime_tz("1-1-2013", "%m-%d-%Y"))
end   = dtutil.dt2ts(dtutil.strptime_tz("1-2-2013", "%m-%d-%Y"))

# download the data and metadata
tags = c.tags("Metadata/Extra/Type = 'oat'")
uuids, data = c.data("Metadata/Extra/Type = 'oat'", start, end)

# pylab timestamps are floating point days since year 1; dtutil knows
# how to convert
def convert_time_vector(tvec):
  return map(lambda t: dtutil.ts2pylabts(t, tzstr='America/Los_Angeles'), 
             tvec / 1000)

# make a dict mapping uuids to data vectors
data_map = dict(zip(uuids, data))

# plot all the data
for timeseries in tags:
  d = data_map[timeseries['uuid']]
  # since we have the tags, we can add some metadata
  label = "%s (%s)" % (timeseries['Metadata/SourceName'],
                       timeseries['Properties/UnitofMeasure'])
  pyplot.plot_date(convert_time_vector(d[:, 0]), d[:, 1], '-', 
                   label=label)

pyplot.legend(loc="lower center")
pyplot.show()
