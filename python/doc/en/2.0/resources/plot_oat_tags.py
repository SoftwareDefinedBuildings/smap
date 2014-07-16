"""Example code plotting one day's worth of outside air time-series,
locating the streams using a metadata query.

@author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
"""

from smap.archiver.client import SmapClient
from smap.contrib import dtutil

from matplotlib import pyplot
from matplotlib import dates

# make a client
c = SmapClient("http://www.openbms.org/backend")

# start and end values are Unix timestamps
start = dtutil.dt2ts(dtutil.strptime_tz("1-1-2013", "%m-%d-%Y"))
end   = dtutil.dt2ts(dtutil.strptime_tz("1-2-2013", "%m-%d-%Y"))

# download the data and metadata
tags = c.tags("Metadata/Extra/Type = 'oat'")
uuids, data = c.data("Metadata/Extra/Type = 'oat'", start, end)

# make a dict mapping uuids to data vectors
data_map = dict(zip(uuids, data))

# plot all the data
for timeseries in tags:
  d = data_map[timeseries['uuid']]
  # since we have the tags, we can add some metadata
  label = "%s (%s)" % (timeseries['Metadata/SourceName'],
                       timeseries['Properties/UnitofMeasure'])
  # we can plot all of the series in their appropriate time zones
  pyplot.plot_date(dates.epoch2num(d[:, 0] / 1000), d[:, 1], '-', 
                   label=label,
                   tz=timeseries['Properties/Timezone'])

pyplot.legend(loc="lower center")
pyplot.show()
