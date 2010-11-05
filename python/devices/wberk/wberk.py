"""sMAP feed polling wunderground data.  Understands the XML spit out
by their feed API.
"""
import sys
import logging
import time
import threading
import urllib2
import rfc822
from xml.dom.minidom import parse, parseString


sys.path.append("../../newlib")
from SmapPoint import SmapPoint, Formatting, Parameter, Reading
import SmapHttp
import SmapInstance
import conf
import smaplog


def get_val(dom, key):
    v = dom.getElementsByTagName(key)[0].firstChild.nodeValue
    return v

class UpdateThread(threading.Thread):
    def __init__(self, inst):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.inst = inst
    
    def run(self):
        last_time = {}
        while True:
            logging.info("Updating meter reading")

            for name, url in conf.CONF.iteritems():
                try:
                    fh = urllib2.urlopen(url, timeout=10)
                except urllib2.URLError, e:
                    logging.error("error getting reading: " + str(e))
                    time.sleep(5)
                    continue

                dom = parse(fh)

                reading_time = rfc822.parsedate_tz(get_val(dom, "observation_time_rfc822"))
                reading_time = int(rfc822.mktime_tz(reading_time))
                if reading_time > last_time.get(name, 0):
                    data = inst['data'][name]['sensor']
                    data['wind_dir'].add(Reading(time=reading_time, value=get_val(dom, "wind_degrees"),
                                                 min=None, max=None))
                    data['wind_speed'].add(Reading(time=reading_time, value=int(10*float(get_val(dom, "wind_mph"))),
                                                   min=None, max=None))
                    data["wind_gust"].add(Reading(time=reading_time, value=int(10*float(get_val(dom, "wind_gust_mph"))),
                                                  min=None, max=None))
                    data["humidity"].add(Reading(time=reading_time, value=int(get_val(dom, "relative_humidity")),
                                                 min=None, max=None))
                    data["temperature"].add(Reading(time=reading_time, value=int(10*float(get_val(dom, "temp_c"))),
                                                    min=None, max=None))
                    data["pressure"].add(Reading(time=reading_time, value=int(10*float(get_val(dom, "pressure_mb"))),
                                                 min=None, max=None))
                    data["dew_point"].add(Reading(time=reading_time, value=int(10*float(get_val(dom, "dewpoint_c"))),
                                                  min=None, max=None))

                    last_time[name] = reading_time

                    inst.push('~/data/' + name)

#                 meter_context['device']['Type'] = get_val(dom, "station_type")
#                 meter_context['device']['Serial'] = get_val(dom, "station_id")
#                 meter_context['location']['Latitude'] = float(get_val(dom, "latitude"))
#                 meter_context['location']['Longitude'] = float(get_val(dom, "longitude"))
#                 meter_context['location']['Elevation'] = get_val(dom, "elevation")
#                 meter_context['location']['Address'] = get_val(dom, "full")
#                 meter_context['meta']['Link'] = get_val(dom, "link")

                dom.unlink()
            time.sleep(60 * 3)

def init_place():
    snsr = {"wind_dir" : SmapPoint(Formatting(unit="deg", multiplier=None, divisor=None, 
                                              type='air', ctype='sensor'),
                                   Parameter(interval=1, time='second')),
            "wind_speed" : SmapPoint(Formatting(unit="m/s", multiplier=44704, divisor=1000000, 
                                                type='air', ctype='sensor'),
                                     Parameter(interval=1, time='second')),
            "wind_gust" :  SmapPoint(Formatting(unit="m/s", multiplier=44704, divisor=1000000, 
                                                type='air', ctype='sensor'),
                                     Parameter(interval=1, time='second')),
            "humidity" : SmapPoint(Formatting(unit="rh", multiplier=None, divisor=None, 
                                              type='air', ctype='sensor'),
                                   Parameter(interval=1, time='second')),
            "temperature" : SmapPoint(Formatting(unit="C", multiplier=None, divisor=10, 
                                                 type='air', ctype='sensor'),
                                      Parameter(interval=1, time='second')),
            "pressure" : SmapPoint(Formatting(unit="Pa", multiplier=10, divisor=None, 
                                              type='air', ctype='sensor'),
                                   Parameter(interval=1, time='second')),
            "dew_point" : SmapPoint(Formatting(unit="C", multiplier=None, divisor=10, 
                                               type='air', ctype='sensor'),
                                    Parameter(interval=1, time='second'))
         }
    return {'sensor' : snsr}

if __name__ == '__main__':
    smaplog.start_log()

    data = {}
    for (name, url) in conf.CONF.iteritems():
        data[name] = init_place()

    inst = SmapInstance.SmapInstance(data, key="wberk")
    u = UpdateThread(inst)
    u.start()

    SmapHttp.start_server(inst, port=conf.SMAP_PORT)
