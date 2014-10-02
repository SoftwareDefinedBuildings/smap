import time
import urllib2
import StringIO
import RPi.GPIO as GPIO
import sys
import time
from smap import driver, util


class PIRSensor(driver.SmapDriver):
    
    def setup(self, opts):
        self.add_timeseries('/Mot1', 'Bool')
        #add_timeseries(self, path, *args, **kwargs):
        self.set_metadata('/Mot1', {
                          'PIR Motion Sensor' : '# 555-28027',
                          'Location':'AMPLAB'
                          })
        self.counter = int(opts.get('StartVal', 0))
    GPIO.setmode(GPIO.BCM)
    PIR_PIN=4
    GPIO.setup(PIR_PIN,GPIO.IN)
    
    def start(self):
        util.periodicSequentialCall(self.read).start(1)
    #def periodicSequentialCall(fn, *args) - any number of arguments, take it as a pointer
    #start(self, interval, now=True) - other 2 arguments are default
    #all these functions are defined in util
    
    def read(self):
        
        reading=GPIO.input(PIR_PIN)
        
        if reading
         self.add('/Mot1', time.time(),self.counter, "Detected")
         print "Detected"
         self.counter += 1
        #count the number of times motion is detected
        
        else
         self.add('/Mot1', time.time(), "No Movement")
         print "Not Detected"


    def stop(self):
     print "Quit"
     GPIO.cleanup()
     self.stopping = True
