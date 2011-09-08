
from distutils.core import setup
import glob

setup(name="Smap",
      version="1.1",
      description="sMAP standard library",
      author="Stephen Dawson-Haggerty",
      author_email="stevedh@eecs.berkeley.edu",
      packages=["smap"],
      requires=["avro", "twisted"],
      package_dir={'smap' : 'smap'},
      package_data={"smap" : ['schema/*.av']},
      scripts=['bin/smap-run-driver', 'bin/smap-run-conf'])
