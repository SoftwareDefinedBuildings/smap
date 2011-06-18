
# smap server port
PORT = 8016

# how often to poll
PERIOD = 30

# list of meters crawled from buildingmanageronline.com

CONF = {   u'Cory Hall': {   u'Electric 5A7': (   u'Power Measurement ION 6200',
                                           u'http://127.0.0.01/setup/devicexml.cgi?ADDRESS=58&TYPE=DATA'),
                      u'Electric 5B7': (   u'Power Measurement ION 6200',
                                           u'http://127.0.0.01/setup/devicexml.cgi?ADDRESS=63&TYPE=DATA')},
    u'Etcheverry Hall': {   u'208 Volt Main Breaker': (   u'Shark 100',
                                                          u'http://127.0.0.01/setup/devicexml.cgi?ADDRESS=77&TYPE=DATA'),
                            u'480 Volt Main Breaker': (   u'Shark 100',
                                                          u'http://127.0.0.01/setup/devicexml.cgi?ADDRESS=76&TYPE=DATA')},
    u'Hearst Mining Bldg': {   u'Electric Meter 120/208': (   u'Shark 100',
                                                              u'http://127.0.0.01/setup/devicexml.cgi?ADDRESS=77&TYPE=DATA'),
                               u'Electric Meter 277/480': (   u'Shark 100',
                                                              u'http://127.0.0.01/setup/devicexml.cgi?ADDRESS=76&TYPE=DATA')}}
