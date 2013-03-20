
default backend = string(default="http://localhost:8079")
location = string(default='')
threadpool size = integer(default=30)

[server]
  [[__many__]]
  port = integer(default=8079)
  interface = string(default="0.0.0.0")
  resources = list(default=list('add', 'api', 'republish'))

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

[readingdb]
module = string(default="readingdb")
host = string(default="localhost")
port = integer(default=4242)
divisor = integer(default=1000)
