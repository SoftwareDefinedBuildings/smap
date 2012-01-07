
import time
import operator

from data import data_load_result

class Request():
    args = {}
    def __str__(self):
        return str(self.args)

def _extract_data(data):
    return data[1]

def _errback(error):
    print error

def extract_data(streams, method, start, end, limit=10, streamlimit=10):
    request = Request()
    request.args = {
        'starttime' : [start],
        'endtime' : [end],
        'limit' : [limit],
        'streamlimit' : [streamlimit]
        }
    d = data_load_result(request, method, streams)
    d.addCallback(_extract_data)
    d.addErrback(_errback)
    
    return d

# from smap.iface.http.httpcurl import get
# import settings

# def make_operator(opname, opargs):
#     if not opname in operators:
#         raise Exception("Unknown opname: " + opname)
#     if len(opargs) != len(operators[opname][1]):
#         raise Exception("Wrong number of arguments for %s: %i" % (opname, len(opargs)))
#     try:
#         bindargs = [cvt(argval) for (cvt, argval) in zip(operators[opname][1], opargs)]
#     except Exception, e:
#         raise Exception("Error converting arguments for %s: %s" % (opname, str(e)))

#     return operators[opname][0], bindargs

# class DataQuery:
#     def __init__(self):
#         self.filters = []
#         self.range = 0, 0
#         self.limit = 1000000

#     def add_filter(self, filter, args):
#         self.filters.reverse()
#         self.filters.append((filter, args))
#         self.filters.reverse()

#     def set_range(self, start, end, limit=10):
#         self.range = start, end

#     def execute(self, request, uid_list):
#         urlbase = 'http://' + ':'.join(map(str, settings.MY_LOCATION)) + \
#             '/api/data/uuid/'
#         query = "?starttime=%i&endtime=%i&limit=%i" % (self.range + (self.limit,))
#         spec = [urlbase + x + query for x in uid_list]
#         start = time.time()
#         data = get(spec)
#         print "data load took", (time.time() - start)
#         data = map(operator.itemgetter(1), data)
#         data = map(operator.itemgetter(0), data)
#         return request, self.apply(data)

#     def apply(self, data):
#         dvecs = [x['Readings'] for x in data]
#         for x in data:
#             del x['Readings']
#         ss = dfop.resample.StreamSet(dvecs, data)
#         for (op, args) in map(lambda x: make_operator(*x), reversed(self.filters)):
#             ss = op(ss, *args)
#         return  map(list, ss.data)

#     def __str__(self):
#         return '('.join(self.filters) + '(' + 'DATA' + ')' * (len(self.filters) + 1) + " [%i, %i]" % self.range
