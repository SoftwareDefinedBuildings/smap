
default backend = string(default="http://localhost:8079")
location = string(default='')
threadpool size = integer(default=30)

[features]
permissions = boolean(default=False)
sketches = boolean(default=False)

[server]
  [[__many__]]
  port = integer(default=8079)
  interface = string(default="0.0.0.0")
  resources = list(default=list('add', 'api', 'republish', 'wsrepublish'))

    [[[ssl]]]
      cert = string()
      key = string()
      cacert = string()
      verify = boolean(default=False)

[database]
module = string(default="smap.archiver.settings")
host = string(default="localhost")
db = string(default="archiver")
user = string(default="archiver")
password = string(default="password")
port = integer(default=5432)
republish = boolean(default=False)

[readingdb]
module = string(default="readingdb")
host = string(default="localhost")
port = integer(default=4242)
divisor = integer(default=1000)

[mongo]
enabled = boolean(default=False)
host = string(default="localhost")
port = integer(default=27017)
keys = list(default=list())
publish_all_private = boolean(default=False)

[statsd]
host = string(default='')
port = integer(default=8125)
prefix = string(default="localhost")
