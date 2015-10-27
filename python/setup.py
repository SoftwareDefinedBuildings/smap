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
import os
import subprocess
from distutils.core import setup, Extension

# SDH : 10/22/2014 : to make setup.py work either in python/ or at the root of the git
# repo, we do this.
# Don't love this, but this means we should be able to install it
# using pip from an source link; that breaks now.
if os.path.basename(os.getcwd()) == 'python':
    os.chdir('..')

# import this to build the parser table so it will be installed
# import smap.archiver.queryparse

# build modbus extension module
modbus_module = Extension('smap.iface.modbus._TCPModbusClient',
                          sources=map(lambda f: "smap/iface/modbus/" + f,
                                      ["TCPModbusClient_wrap.c", "TCPModbusClient.c",
                                       "utility.c", "crc16.c", "DieWithError.c",
                                       "HandleModbusTCPClient.c"]))

inc_dir = ['bacnet-stack-0.6.0/include', 
           'bacnet-stack-0.6.0/demo/object',
           'bacnet-stack-0.6.0/ports/linux']

# Use absolute paths relative to setup.py
# in order to build BACnet support, first download bacnet-stack-0.6 from here:
# http://sourceforge.net/projects/bacnet/files/bacnet-stack/bacnet-stack-0.6.0/
# 
# build that source for your platform (on OSX, make sure you do
# everything with CC=gcc; none of this works wtih LLVM).
#
# you should then be able to uncomment the bacnet extension module and
# build pybacnet
prefix = os.path.dirname(os.path.abspath(__file__))
inc_dir = [os.path.join(prefix, dir) for dir in inc_dir]
lib_path = os.path.join(prefix, 'bacnet-stack-0.6.0/lib')
bacnet_module = Extension('smap.iface.pybacnet._bacnet',
  sources=['smap/iface/pybacnet/bacnet.c', 'smap/iface/pybacnet/bacnet.i'],
  swig_opts=['-I' + os.path.join(prefix, 'bacnet-stack-0.6.0/include')],
  libraries=['bacnet'],
  library_dirs=[lib_path],
  include_dirs=inc_dir)


def git_rev():
    try:
        # this works when building to add the git repo but when
        # distributing, it's not in a git repo so we we stash the
        # current version in VERSION, and include it in MANIFEST.in
        version = subprocess.check_output(['git', 'rev-parse', 'HEAD'])
        with open('VERSION', 'w') as fp:
            print >>fp, version
        return version
    except subprocess.CalledProcessError, e:
        return open('VERSION', 'r').read()


setup(name="Smap",
      version='2.0.R' + git_rev()[:6],
      description="sMAP standard library and drivers",
      author="Stephen Dawson-Haggerty",
      author_email="stevedh@eecs.berkeley.edu",
      url="http://code.google.com/p/smap-data",
      license="BSD",
      packages=[
        # core sMAP libs and drivers
        "smap", 
        "smap.drivers", 
        "smap.contrib",
        "smap.ops",

	"twisted.plugins",

        # smap archiver components
        "smap.archiver",

        # interfaces for talking to different backends
        "smap.iface", "smap.iface.http", "smap.iface.modbus",
        "smap.iface.modbustcp",
        "smap.iface.pybacnet",

        # hack to support ipv6 sockets -- needed for acme, at least
        "tx", "tx.ipv6", "tx.ipv6.application", "tx.ipv6.internet",

        # various extra divers and dependencies -- might want to leave this out on mainline
        "smap.drivers.obvius",
        # packages for the acme driver -- don't install this in trunk/
        "smap.drivers.acmex2", "tinyos", "tinyos.message",

        # "smap.drivers.labjack", "smap.drivers.labjack.labjackpython",
        ],
      requires=["avro", "dateutil", "twisted", "ordereddict", 
                "ply", "psycopg2", "numpy", "scipy", "simplejson"],
      package_dir={"" : "python"},
      package_data={"smap" : ['schema/*.av', 
                              'archiver/sql/*.psql',
                              'archiver/settings.spec',
                              'data/*.html'],
                    "conf": ['*.ini'],
                    },
      data_files=[
        # ('/etc/supervisor/conf.d/', ['supervisor/archiver.conf']),
        # ('/etc/monit/conf.d', ['monit/archiver']),
        # ('/etc/smap/', ['conf/archiver.ini']),
        ],
      ext_modules=[
        # modbus_module,
        # bacnet_module,
        ],
      scripts=['python/bin/jprint', 'python/bin/uuid', 'python/bin/smap-query', 
               'python/bin/smap-run-driver', 'python/bin/smap-load',
               'python/bin/smap-load-csv', 'python/bin/smap-tool',
               'python/bin/smap-reporting', 'python/bin/smap-monitize',
               'python/bin/smap-subscribe'],
      install_requires = [
        'twisted', 'configobj', 'avro', 'python-dateutil', 'lockfile'])
