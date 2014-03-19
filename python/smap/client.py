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
"""
@author Tyler Hoyt <thoyt@berkeley.edu>
"""

import urllib2
import time

from smap import util
from smap.core import SmapException
import smap.sjson as json

class SmapClient:

    def __init__(self, base):
        """
        :param string base: URL of the smap source
        """
        self.base = base
        try:
            fp = urllib2.urlopen(self.base)
            fp.read()
        except Exception, e:
          raise SmapException("sMAP source not found.")

    def get_state(self, path):
        fp = urllib2.urlopen(self.base + "/data" + path)
        res = json.loads(fp.read())
        if 'Readings' not in res:
            raise SmapException("Readings not found. \
              Make sure the path corresponds to a timeseries (not a collection)")
        else:
            try: 
                rv = res['Readings'][0]
            except IndexError:
                raise SmapException("The timeseries doesn't have any readings")
        return rv

    def set_state(self, path, state):
        url = self.base + "/data" + path + "?state=" + str(state)
        opener = urllib2.build_opener(urllib2.HTTPHandler)
        request = urllib2.Request(url, data='')
        request.get_method = lambda: 'PUT'
        try: 
            fp = opener.open(request)
        except urllib2.HTTPError:
            raise SmapException("Invalid path.")
        res = json.loads(fp.read())
        if 'Actuator' not in res:
            raise SmapException("Path does not locate an actuator.")
        elif res['Readings'][0][1] != state:
            raise SmapException("Actuaton failed")
        else:
            return 0
 
    def submit_jobs(self, jobs):
        """
        jobs is an array of job objects: 
        job is an object that is formed according to ../schema/job.av
        properties: Name (str), StartTime (longint), Actions (array)
        where actions is an array where each entry is an object
        with properties State (longint or double) and Path (str)
        """ 
        url = self.base + '/jobs'
        payload = json.dumps(jobs)
        opener = urllib2.build_opener(urllib2.HTTPHandler)
        request = urllib2.Request(url, data=payload)
        request.get_method = lambda: 'PUT'
        fp = opener.open(request)
        rv = json.loads(fp.read())
        return rv
  
    def cancel_jobs(self, job_ids):
        url = self.base + '/jobs'
        payload = json.dumps(job_ids)
        opener = urllib2.build_opener(urllib2.HTTPHandler)
        request = urllib2.Request(url, data=payload)
        request.add_header('Content-Type', 'your/contenttype')
        request.get_method = lambda: 'DELETE'
        fp = opener.open(request)
        rv = json.loads(fp.read())
        return rv

    def tags(self, path):
        """ 
        Get all metadata associated with path, including metadata 
        inherited from collections it belongs to
        """
        nodes = path.split('/')
        p = ""
        rv = {}
        for node in nodes:
            p += '/' + node
            fp = urllib2.urlopen(self.base + "/data" + p)
            res = json.loads(fp.read())
            rv = util.dict_merge(rv, res)
        if 'Contents' in rv:
            del rv['Contents']
        return rv

    def contents(self, path='/'):
        """
        Get a list of the paths of timeseries in a collection.
        Will search the root collection by default.
        """
        fp = urllib2.urlopen(self.base + "/data" + path)
        res = json.loads(fp.read())
        if "Readings" in res:
            # Found a timeseries
            actuator = "Actuator" in res
            return {'Path': path, 'uuid': res['uuid'], 'Actuator': actuator}
        elif "Contents" in res:
            # Found a collection 
            acc = []
            for item in res["Contents"]:
                p = path + item + "/"
                c = self.contents(p)
                try:
                    acc = acc + c
                except TypeError:
                    acc.append(c)
            return acc

if __name__=='__main__':
    # Example for use with example driver
    from smap.client import SmapClient
    import time

    c = SmapClient("http://127.0.0.1:8080")
    path = '/instrument0/sensor0'

    print 'Tags:', c.tags(path), '\n'
    print 'Current reading:', c.get_state(path), '\n'
    print 'Contents:', c.contents(), '\n'

    path = '/binary/point0'
    print 'Setting state succeeds:', c.set_state(path, 0), '\n'

    path = '/binary/point0'
    start_time = time.time() * 1000 + 20 * 1000 # 20s from now
    jobs = [{
        'StartTime': start_time, 
        'Name': 'Job1',
        'Actions': [
            {'State': 0, 'Path': path},
            {'State': 1, 'Path': path},
            {'State': 0, 'Path': path},
            {'State': 1, 'Path': path}
        ]   
    }]
    del_uuids = c.submit_jobs(jobs)
    print 'Submit a job:', del_uuids, '\n'

    print 'Cancel the job:', c.cancel_jobs(del_uuids), '\n'

    jobs.append({
        'After': 'Job1',
        'Name': 'Job2',
        'Actions': [
            {'State': 0, 'Path': path},
            {'State': 1, 'Path': path},
            {'State': 0, 'Path': path},
            {'State': 1, 'Path': path}
        ]
    })
    del_uuids = c.submit_jobs(jobs)
    print 'Submit two jobs:', del_uuids, '\n'

    del_uuids.pop(0)
    print 'Cancelling the second job cancels the queue:', c.cancel_jobs(del_uuids), '\n'
