
from distutils.core import setup

setup(name="Smap",
      version="1.1",
      description="sMAP standard library",
      author="Stephen Dawson-Haggerty",
      author_email="stevedh@eecs.berkeley.edu",
      packages=["smap"],
      requires=["avro", "twisted"])
