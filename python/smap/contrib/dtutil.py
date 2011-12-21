'''
Datetime utilities. Convert between strings, timestamps and aware datetime objects.
Also, includes matplotlib helpers to setup date plotting.

@author Andrew Krioukov
'''

from dateutil.tz import *
import datetime, calendar

utc = gettz('UTC')
local = tzlocal()

def now(tzstr = 'UTC'):
  '''Returns an aware datetime object with the current time in tzstr timezone'''
  if tzstr == 'Local':
    tz = local
  else:
    tz = gettz(tzstr)
  return datetime.datetime.now(tz)

def strptime_tz(str, format='%x %X', tzstr='Local'):
  '''Returns an aware datetime object. tzstr is a timezone string such as
     'US/Pacific' or 'Local' by default which uses the local timezone.
  '''
  dt = datetime.datetime.strptime(str, format)
  if tzstr == 'Local':
    tz = local
  else:
    tz = gettz(tzstr)
  return dt.replace(tzinfo = tz)

def strftime_tz(dt=None, format='%x %X', tzstr=None):
  '''Returns a string from an aware datetime object. tzstr specifies the
     timezone of the result. A value of None uses the datetime object's timezone
     and a value of 'Local' uses the local system timezone.'''
  if dt == None:
    dt = now('Local')

  if not dt.tzinfo:
    raise ValueError('dt must be an aware datetime')

  if tzstr:
    if tzstr == 'Local':
      tz = local
    else:
      tz = gettz(tzstr)
    dt = dt.astimezone(tz)
  return dt.strftime(format)

def dt2ts(dt):
  '''Convert an aware datetime object to a UTC timestamp.'''
  if not dt.tzinfo:
    raise ValueError('dt must be an aware datetime')
  return calendar.timegm(dt.utctimetuple())

def ts2dt(ts):
  '''Convert a UTC timestamp to an aware datetime object with UTC timezone'''
  return datetime.datetime.utcfromtimestamp(ts).replace(tzinfo=utc)

def ts2pylabts(ts, tzstr='UTC'):
  '''Convert a UTC timestamp to float days since 0001-01-01 UTC.'''
  tz = gettz(tzstr)
  dt = datetime.datetime.utcfromtimestamp(ts).replace(tzinfo=tz)
  dt_0 = datetime.datetime(year=1, month=1, day=1, tzinfo=gettz('UTC'))
  # timedelta converts everything to days and seconds
  delta = dt - dt_0
  return delta.days + (delta.seconds / (3600. * 24))

def ts(str, format='%x %X', tzstr='Local'):
  return dt2ts(strptime_tz(str, format, tzstr))
