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

from distutils.core import setup, Extension

# import this to build the parser table so it will be installed
# import smap.archiver.queryparse

# build modbus extension module
modbus_module = Extension('smap.iface.modbus._TCPModbusClient',
                          sources=map(lambda f: "smap/iface/modbus/" + f,
                                      ["TCPModbusClient_wrap.c", "TCPModbusClient.c",
                                       "utility.c", "crc16.c", "DieWithError.c",
                                       "HandleModbusTCPClient.c"]))

setup(name="Smap",
      version="2.0.558",
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
      # package_dir={"smap" : "smap"},
      package_data={"smap" : ['schema/*.av', 
                              'archiver/sql/*.psql',
                              'archiver/settings.spec',
                              'data/*.html'],
                    "conf": ['*.ini'],
                    },
      data_files=[
        # ('/etc/monit/conf.d', ['monit/archiver']),
        # ('/etc/smap/', ['conf/archiver.ini']),
        ],
      # ext_modules=[modbus_module],
      scripts=['bin/jprint', 'bin/uuid', 'bin/smap-query', 
               'bin/smap-run-driver', 'bin/smap-load',
               'bin/smap-load-csv', 'bin/smap-tool',
               'bin/smap-reporting', 'bin/smap-monitize'],
      install_requires = [
        'twisted', 'configobj', 'avro', 'python-dateutil'])
