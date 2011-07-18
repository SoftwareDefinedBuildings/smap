
import time
import re
import json
import uuid

def now():
    return int(time.time()) * 1000

def split_path(path):
    path = re.split('/+', path)
    return filter(lambda x: len(x), path)
    # return path

def join_path(path):
    return '/' + '/'.join(path)

norm_path = lambda x: join_path(split_path(x))

class UuidEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, uuid.UUID):
            return str(obj)
        return json.JSONEncoder.default(self, obj)

def dump_json(obj, fp):
    json.dump(obj, fp, cls=UuidEncoder)


class FixedSizeList(list):
    """
    A class for keeping a circular buffer with a maximum size.
    Used for storing a fixed history of "profile" data.
    """
    def __init__(self, size=None, sort_profile=False):
        self.size = size
        self.sort_profile = sort_profile
        list.__init__(self)
    
    def append(self, val):
        if self.sort_profile == True:
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
