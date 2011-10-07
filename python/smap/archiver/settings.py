
# my local hostname and port to run the twisted server on.  the
# hostname should be something smap sources can send their data to
MY_LOCATION = ('smote.cs.berkeley.edu', 8079)

# how often sMAP report instances should time out
EXPIRE_TIME = None
# how often we should check that we are still subscribed to all the
# sMAP sources.
CHECK_TIME = None

# the location of the readingdb server which holds the timeseries
READINGDB = ('gecko.cs.berkeley.edu', 4243)

# mysql setup for metadata and other tables
MYSQL_HOST = 'jackalope.cs.berkeley.edu'
MYSQL_DB = 'archiver'
MYSQL_USER = 'ar'
MYSQL_PASS = 'K55VnsPT'

