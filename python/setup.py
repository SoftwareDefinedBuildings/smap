
from distutils.core import setup
import glob

setup(name="Smap",
      version="2.0",
      description="sMAP standard library and drivers",
      author="Stephen Dawson-Haggerty",
      author_email="stevedh@eecs.berkeley.edu",
      packages=[
        # core sMAP libs and drivers
        "smap", 
        "smap.drivers", 
        "smap.contrib",

        # smap archiver components
        "smap.archiver",

        "twisted", "twisted.plugins",

        # interfaces for talking to different backends
        "smap.iface", "smap.iface.http", "smap.iface.modbus",

        # hack to support ipv6 sockets -- needed for acme, at least
        "tx", "tx.ipv6", "tx.ipv6.application", "tx.ipv6.internet",

        # various extra divers and dependencies -- might want to leave this out on mainline
        "smap.drivers.obvius",
        # packages for the acme driver -- don't install this in trunk/
        "smap.drivers.acmex2", "tinyos", "tinyos.message",
        ],
      requires=["avro", "twisted"],
      package_dir={"smap" : "smap"},
      package_data={"smap" : ['schema/*.av']},
      scripts=['bin/smap-run-driver', 'bin/smap-run-conf', 
               'bin/jprint', 'bin/uuid'])
