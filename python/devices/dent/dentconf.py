# configuration for Dent PowerScout 18 meters.  Each CONFIG value
# should contain a (hostname, port, modbus_addr) tuple.

RATE = 20
PORT = 8005

CONFIG = {
    "basement-1" : ("10.0.50.101", 4660, 1),
    "basement-2" : ("10.0.50.102", 4660, 1),
    "basement-3" : ("10.0.50.103", 4660, 1),    
    "gpw" : ("10.0.50.121", 4660, 1),    
    }
