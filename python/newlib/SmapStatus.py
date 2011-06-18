
import time

class SmapStatus:
    def __init__(self):
        self.boot_time = int(time.time())
    
    def http_get(self, request, resource, query=None):
        now = int(time.time())
        return {
            'status' : 1,
            'Uptime' : int(now - self.boot_time),
            'LocalTime' : now
            }
