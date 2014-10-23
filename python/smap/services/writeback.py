from smap.archiver.client import SmapClient
from smap.util import periodicSequentialCall, buildkv
from smap.driver import SmapDriver

from twisted.internet.utils import getProcessOutputAndValue
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

    def start(self):
        periodicSequentialCall(self.query).start(self.rate)

    def _git_commit(self):
        """
        If there is a .git directory in self.smap_ini_dir, we do a commit
        after we finish mirroring the metadata back to the ini files
        """
        if os.path.exists(os.path.join(self.smap_ini_dir, '.git')):
            print ' '.join(self.uuid_conf.values())
            script = """
git add {0};
git commit -m "update ini files via writeback";
git push origin master""".format(' '.join(self.uuid_conf.values()))
            d = getProcessOutputAndValue("/bin/sh", args=["-c", script], path=self.smap_ini_dir)
            def check((stdout, stderr, code)):
                print stdout
                print stderr
                if code != 0: #failure
                    raise Exception(stderr)
            d.addCallback(check)
        else:
            print 'no directory .git found in {0}'.format(self.smap_ini_dir)

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
                if path not in c:
                    c[path] = {}
                for k,v in kvs:
                    c[path][k] = v
            c.write()
        self._git_commit()
