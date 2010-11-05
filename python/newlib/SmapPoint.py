
import time
import collections
import bisect

import SmapHttp

Reading    = collections.namedtuple("Reading", "time value min max")
Formatting = collections.namedtuple("Formatting", "unit multiplier divisor type ctype")
Parameter  = collections.namedtuple("Parameter", "interval time")

class FixedSizeList(list):
    """
    A class for keeping a circular buffer with a maximum size.
    Used for storing a fixed history of "profile" data.
    """
    def __init__(self, size=None, sorted=False):
        self.size = size
        self.sorted = sorted
        list.__init__(self)
    
    def append(self, val):
        if self.sorted:
            # Find insert point in sorted list
            idx = bisect.bisect_left([r.time for r in self], val.time)
            # Ignore duplicate times
            if idx >= len(self) or self[idx].time != val.time:
                self.insert(idx, val)
            else:
                return False
        else:
            list.append(self, val)

        if self.size and len(self) > self.size:
            self.pop(0)

        return True

    def set_size(self, size):
        if len(self) > size:
            self.__delslice__(0, self.size  - size)
        self.size = size

class SmapPoint:
    """
    Represents a single sMAP sense or meter point.  

    This class is what is found at the leaves of the resource tree
    under data/.
    """
    def __init__(self, formatting, parameter, extra_parameters=None):
        self.formatting = formatting
        self.parameter = parameter
        self.profile = FixedSizeList(200, sorted)
        self.extra_parameters = extra_parameters

    def add(self, reading):
        """
        Add a reading to this smap "point"; the reading must have type
        of SmapPoint.Reading.

        This will add the reading to the profile data.
        """
        SmapHttp.lock()
        try:
            if not isinstance(reading, Reading):
                raise Exception("Invalid reading")
            return self.profile.append(reading)
        finally:
            SmapHttp.release()

    def get_resources(self):
        """Get the resource a SmapPoint provides as a python list"""
        return ['reading', 'parameter', 'profile', 'formatting']

    def get_reading(self, reading):
        """Get the latest reading as an object conforming to the sMAP schema"""
        obj = {
            "$schema" : {"$ref" : "http://webs.cs.berkeley.edu/schema/sensor/reading"},
            "Version" : 1,
            "Reading" : reading.value,
            "ReadingTime" : reading.time,
            }
        if reading.min:
            obj["Min"] = reading.min
        if reading.max:
            obj["Max"] = reading.max
        return obj

    def get_formatting(self, fmt):
        obj = {
            "Version" : 1,
            "$schema" : {},
            "UnitofMeasure" : fmt.unit,
            "UnitofTime" : 'second',
            "MeterType" : fmt.type,
            "ChannelType" : fmt.ctype,
            }

        if fmt.multiplier and fmt.multiplier != 1:
            obj["Multiplier"] = fmt.multiplier
        if fmt.divisor and fmt.divisor != 1:
            obj["Divisor"] = fmt.divisor
        return obj

    def get_parameter(self, param):
        if len(self.profile) > 0:
            elapsedtime = int(time.time() - self.profile[-1].time)
        else:
            elapsedtime = None
            
        obj = {
            "$schema" : {"$ref" : "http://webs.cs.berkeley.edu/schema/meter/parameter"},
            "Version" : 1,
            "IntervalSinceLastReading" : elapsedtime,
            "UnitofTime" : param.time,
            "SamplingPeriod" : param.interval,
            }
        if self.extra_parameters:
            obj['Additional'] = self.extra_parameters

        return obj

    def http_get(self, resource, query=None):
        """
        Return a python object corresponding to the resource
        """
        if len(resource) == 0:
            return ['reading', 'formatting', 'parameter', 'profile']
        else:
            resource = resource[0]

        if resource == 'reading':
            if len(self.profile) == 0: return None
            return self.get_reading(self.profile[-1])
        elif resource == 'formatting':
            return self.get_formatting(self.formatting)
        elif resource == 'parameter':
            return self.get_parameter(self.parameter)
        elif resource == 'profile':
            return [self.get_reading(x) for x in self.profile]
