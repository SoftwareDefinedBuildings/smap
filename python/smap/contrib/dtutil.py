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

def ts2dt(ts, tzinfo=utc):
  '''Convert a UTC timestamp to an aware datetime object with UTC timezone'''
  return datetime.datetime.utcfromtimestamp(ts).replace(tzinfo=tzinfo)

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
