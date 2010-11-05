# configuration for a Dent Powerscout 3
# it's just like a PowerScout 18, but there's only one three-phase meter. 

PORT = 8004

TYPE='dent3'

# a list of email address to be notified of ERROR and WARN log messages
# EMAIL=['stevedh@eecs.berkeley.edu']

CONFIG = {
    "p175" : ("10.0.50.120", 4660, 1),
    }
