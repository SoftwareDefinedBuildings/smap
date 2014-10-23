from smap.archiver.client import SmapClient
from smap.util import periodicSequentialCall, buildkv
from smap.driver import SmapDriver

from itertools import groupby
from configobj import ConfigObj
import os
import glob

class WriteBack(SmapDriver):
    def setup(self, opts):
        self.archiver_url = opts.get('archiver','http://localhost:8079')
        self.smap_ini_dir = opts.get('smap_dir','/etc/smap')
        self.rate = int(opts.get('rate',300))
        self.client = SmapClient(self.archiver_url)
        self.uuid_conf = {}

        # identify which file corresponds to which sourcename
        for ini in glob.glob(os.path.join(self.smap_ini_dir, '*.ini')):
            c = ConfigObj(ini)
            if '/' in c and 'Metadata/SourceName' in c['/']:
                self.uuid_conf[c['/']['Metadata/SourceName']] = ini
        print self.uuid_conf

    def start(self):
        periodicSequentialCall(self.query).start(self.rate)

    def _get_prefixes(self, path):
        components = path.split('/')
        base = ''
        for component in components[1:-1]:
            base += '/' + component
            yield base

    def query(self):
        # get all sourcenames
        sources = self.client.query("select distinct Metadata/SourceName")
        for source in sources:
            md = {}
            res = self.client.query("select * where Metadata/SourceName = '{0}'".format(source))
            paths = map(lambda x: x['Path'], res)
            # find the unique set of path prefixes
            pathset = set()
            for path in paths:
                for prefix in self._get_prefixes(path):
                    pathset.add(prefix)
            pathset = sorted(list(pathset), key = lambda x: len(x)) # start at root and build up
            # build list of kv-pairs for each dictionary of metadata
            for path_dict in res:
                kv = buildkv('Metadata',path_dict['Metadata'])
                md[path_dict['Path']] = set(kv)
            c = ConfigObj(self.uuid_conf[source])
            path_kv = {}
            for path in pathset:
                kvs = set.intersection(*[v for k,v in md.iteritems() if k.startswith(path)])
                for prefix in self._get_prefixes(path):
                    kvs.difference_update(path_kv[prefix])
                path_kv[path] = kvs
                print path, kvs
                if path not in c:
                    c[path] = {}
                for k,v in kvs:
                    c[path][k] = v
            c.write()
