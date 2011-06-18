
import sys
import logging
import time
import threading
import urllib2

sys.path.append("../../newlib")
import smaplog
import SmapInstance
import SmapHttp
import SmapPoint
urllib2.install_opener(urllib2.build_opener())

if __name__ == '__main__':
    smaplog.start_log()
    data = {
        'CA' : {
          'meter' : {
            '0' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='kW',
                                                           multiplier=1000,
                                                           divisor=None,
                                                           type='electric',
                                                           ctype='sensor'),
                                      SmapPoint.Parameter(interval=60*10,
                                                          time='second'))
            }
          }
        }
    inst = SmapInstance.SmapInstance(data, key='caiso')
    SmapHttp.start_server(inst, port=8002, background=True)

    lastProduced = None
    while True:
        logging.info("Updating meter reading")
        object_ = {}
        try:
            fh = urllib2.urlopen('http://www.caiso.com/outlook/systemstatus.csv')
            for line in fh.readlines():
                kv = line.strip().split(',')
                object_[kv[0]] = kv[1]
        except urllib2.URLError:
            pass
        except urllib2.HTTPError:
            pass
        except IOError:
            pass
        else:
            thisTime = int(time.mktime(time.strptime(object_['Produced'])))
            if lastProduced == None or lastProduced != thisTime:
                logging.info("Updated reading")
                inst['data']['CA']['meter']['0'].add( \
                    SmapPoint.Reading(time=thisTime,
                                      value=object_['Actual Demand'],
                                      min=None,
                                      max=None))
                lastProduced = thisTime
                inst.push()
            fh.close()
        time.sleep(60 * 5)
