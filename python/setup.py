
from distutils.core import setup
import glob

setup(name="Smap",
      version="1.1",
      description="sMAP standard library and drivers",
      author="Stephen Dawson-Haggerty",
      author_email="stevedh@eecs.berkeley.edu",
      packages=["smap", # "smap.drivers", 
                "smap.contrib",
                "smap.iface", "smap.iface.http", "smap.iface.modbus",
                "smap.drivers.obvius",
                # packages for the acme driver -- don't install this in trunk/
                "smap.drivers.acmex2", "tinyos", "tinyos.message",
                # hack to support ipv6 sockets -- needed for acme, at least
                "tx", "tx.ipv6", "tx.ipv6.application", "tx.ipv6.internet"
                ],
      requires=["avro", "twisted"],
      package_dir={"smap" : "smap"},
      package_data={"smap" : ['schema/*.av']},
      scripts=['bin/smap-run-driver', 'bin/smap-run-conf'])
