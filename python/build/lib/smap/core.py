
import uuid
from zope.interface import implements
from twisted.web import resource

import schema
import util
from interface import *

class SmapException(Exception):
    """Generic error"""

class SmapSchemaException(SmapException):
    """Exception generated if a json object doesn't validate as the
appropriate kind of schema"""


class Timeseries(dict):
    """Represent a single Timeseries"""
    implements(ITimeseries)

    TIMESERIES_FIELDS = [
        "Readings", "Description", "Metadata", "Properties", "uuid"]

    def __init__(self,
                 new_uuid,
                 unit, 
                 data_type="long", 
                 timezone="America/Los_Angeles",
                 description=None,
                 buffersz=1):
        self.__setitem__("uuid", new_uuid)
        self.__setitem__("Properties", {
                'UnitofMeasure' : unit,
                'ReadingType' : data_type,
                'Timezone' : timezone})
        self.__setitem__("Readings", util.FixedSizeList(buffersz))
        if description:
            self.__setitem__("Description", description)

    def _check_type(self, value):
        type_ = self.__getitem__('Properties')['ReadingType']
        if type_ == 'long' and \
                (isinstance(value, int) or isinstance(value, long)):
            return True
        elif type_ == 'double' and \
                isinstance(value, float):
            return True
        else:
            return False

    def add(self, time, value, seqno=None):
        """Add a new reading to this timeseries"""
        if not self._check_type(value):
            raise SmapException("Attempted to add " + str(value) + " to Timeseries, but " 
                                "the timeseries type is " + self.__getitem__('Properties')['ReadingType'])
        reading = {
            "ReadingTime" : time,
            "Reading" : value,
            }
        if seqno: reading["ReadingSequence"] = seqno
        self.__getitem__("Readings").append(reading)

    def __setitem__(self, attr, value):
        if attr in self.TIMESERIES_FIELDS:
            dict.__setitem__(self, attr, value)
            if attr != 'uuid':
                if not schema.validate("Timeseries", self):
                    raise SmapSchemaException("Invalid schema in Timeseries for " + attr)
        else:
            raise KeyError(attr + " can not be set on a Timeseries!")

class Collection(dict):
    """Represent a collection of sMAP resources"""
    implements(ICollection)
    def __init__(self,
                 new_uuid,
                 description=None):
        self.__setitem__("uuid", new_uuid)
        self.__setitem__("Contents", {})
        self.__setitem__("Proxy", False)
        if not schema.validate("Collection", self):
            raise SmapSchemaException("Error instantiating Collection: invalid parameter")
        
    def add_child(self, name, child):
        if not ITimeseries.providedBy(child) and \
                not ICollection.providedBy(child):
            raise SmapException("Children of collections must be either collections or timeseries!")
        contents = self.__getitem__("Contents")
        contents[name] = child['uuid']

    def set_metadata(self, metadata):
        if not schema.validate("Metadata", metadata):
            raise SmapSchemaException(str(metadata) + " is not a valid Metadata object")
        self.__setitem__("Metadata", metadata)

class SmapServer:
    """The UUID of the root of this smap source.  Used to generate other
    uuids within the server."""
    def __init__(self, root_uuid):
        self.OBJS_PATH = {}
        self.OBJS_UUID = {}
        self.USED_KEYS = {}
        self.add_collection("/", Collection(root_uuid))

    def uuid(self, key):
        if key and self.OBJS_PATH.get('/'):
            if key in self.USED_KEYS:
                raise SmapException("Cannot create uuid based on key " + key + \
                                        ": key already in use!")
            self.USED_KEYS[key] = True
            return uuid.uuid5(self.OBJS_PATH['/']['uuid'], key)
        else:
            raise Exception("Timeseries cannot generate uuid: must "
                            "specifiy either uuid or key and ROOT_UUID")
    
    def lookup(self, id, pred=None):
        """Retrieve an object in the resource hierarchy by path or uuid"""
        if isinstance(id, uuid.UUID):
            obj = self.OBJS_UUID.get(id, None)
        elif isinstance(id, str):
            path = util.split_path(id)
            pred = None
            if len(path) > 0 and path[-1][0] == "+":
                if "Timeseries".startswith(path[-1][1:]):
                    pred = ITimeseries.providedBy
                elif "Collections".startswith(path[-1][1:]):
                    pred = ICollection.providedBy
                else:
                    obj = None
                return self._lookup_r(util.join_path(path[:-1]), pred=pred)
            else:
                obj = self.OBJS_PATH.get(util.join_path(path), None)
        else:
            obj = None

        if not pred or pred(obj):
            return obj
        else: return None

    def _lookup_r(self, id, pred=None):
        """Lookup recursively in the resource hierarchy, starting with the
        resource identifed by "id".  Returns a list of elements for which
        "pred" returns True"""
        rv = []
        q = [id]

        while len(q) > 0:
            cur = self.lookup(q.pop(0))
            if ICollection.providedBy(cur):
                for child in cur['Contents'].itervalues():
                    q.append(child)
            if cur and (not pred or pred(cur)):
                rv += [cur]
        return rv

    get_timeseries = lambda self, id: self.lookup(id, pred=ITimeseries.providedBy)
    get_collection = lambda self, id: self.lookup(id, pred=ICollection.providedBy)

    def add_timeseries(self, path, timeseries):
        """Add a timeseries to the smap server at the given path.  This will
        generate a UUID for the timeseries. """
        if not ITimeseries.providedBy(timeseries):
            raise Exception("add_timeseries arguments must implement ITimeseries")

        path = util.split_path(path)
        parent = self.get_collection(util.join_path(path[:-1]))

        if util.join_path(path) in self.OBJS_PATH:
            raise SmapException("add_timeseries: path " + str(path) + " exists!")
        if not parent:
            raise SmapException("add_timeseries: parent is not a collection!")
        parent.add_child(path[-1], timeseries)

        # place the new timeseries into the uuid and path tables
        self.OBJS_UUID[timeseries['uuid']] = timeseries
        self.OBJS_PATH[util.join_path(path)] = timeseries

    def add_collection(self, path, collection):
        if not ICollection.providedBy(collection):
            raise Exception("add_collection argument must implement ICollection")
        path = util.split_path(path)
        if len(path) > 0:
            parent = self.get_collection(util.join_path(path[:-1]))
            if not parent:
                raise SmapException("add_collection: parent is not collection!")
            parent.add_child(path[-1], collection)
        if util.join_path(path) in self.OBJS_PATH:
            raise SmapException("add_timeseries: path " + str(path) + " exists!")

        self.OBJS_UUID[collection['uuid']] = collection
        self.OBJS_PATH[util.join_path(path)] = collection



if __name__ == '__main__':
    ROOT_UUID = uuid.uuid1()
    s = SmapServer(ROOT_UUID)
    s.add_collection("/steve", Collection(s.uuid("steve")))
    t = Timeseries(s.uuid("sdh"), "V", buffersz=2)
    s.add_timeseries("/sensor0", t)
    # print t
    t.add(util.now(), 12)
    t.add(util.now(), 13)
    print s.get_timeseries(t['uuid'])
    print s.get_timeseries('/sensor0')
    print s.get_timeseries('/')

#    s.get_collection('/').set_metadata({'Extra' : {"foo": " bar"}})
    print s.get_collection('/')


#     print "Finding all Timeseries under /"
    print s._lookup_r('/', pred=ITimeseries.providedBy)
    print s.lookup('/+Timeseries')
#     print _lookup_r('/', pred=ICollection.providedBy)

    # print s._lookup_r("/foo")
