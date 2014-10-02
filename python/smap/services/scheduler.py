import urlparse
import datetime
import urllib2
from smap.driver import SmapDriver
from smap.util import periodicSequentialCall
from smap.contrib import dtutil

class Scheduler(SmapDriver):
    def setup(self, opts):
        self.schedule = self.load_schedule(opts.get('source'))
        self.pollrate = float(opts.get('pollrate', 1))
        self.publishrate = float(opts.get('publishrate', 300))
        self.day_map = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']
        self.previous_period = None
        self.changed = False
        self.add_timeseries('/temp_heat', 'F', data_type='long')
        self.add_timeseries('/temp_cool', 'F', data_type='long')
        self.add_timeseries('/on', 'On/Off', data_type='long')
        self.add_timeseries('/hvac_state', 'Mode', data_type='long')
        self.is_mongo = urlparse.urlparse(opts.get('source')).scheme == 'mongodb'

    def start(self):
        periodicSequentialCall(self.read).start(self.pollrate)
        if self.publishrate:
            periodicSequentialCall(self.publish).start(self.publishrate)


    def read(self):
        master_sched = self.master_schedule
        self.now = datetime.datetime.now()
        day = self.day_map[self.now.weekday()]

        today_sched = self.get_schedule(master_sched[day])
        current_period = self.get_current_period(today_sched)
        self.changed = self.previous_period != current_period
        self.previous_period = current_period

        if not current_period:
            # carry over from yesterday
            yest = self.day_map[self.now.weekday()-1]
            yest_sched = self.get_schedule(master_sched[yest])
            temp_latest = datetime.time(0,0,0)
            for p in yest_sched['periods']:
                hour, minute = p['start'].split(':')
                start = datetime.time(int(hour), int(minute), 0)
                if start > temp_latest:
                    current_period = p
                    temp_latest = start
            current_period['_done'] = False

        self.schedule_points = current_period['points']
        if self.changed:
            for sp in self.schedule_points:
                print 'SCHEDULE',sp['path'],sp['value']
                self.add('/'+sp['path'], int(sp['value']))
        else:
            print self.schedule_points

    def publish(self):
        if self.schedule_points:
            for sp in self.schedule_points:
                print 'regular publish SCHEDULE',sp['path'],sp['value']
                self.add('/'+sp['path'], int(sp['value']))


    def get_schedule(self, sched_type):
        if self.is_mongo:
            return self.schedules.find_one({'name': sched_type})
        # otherwise...
        for schedule in self.schedules:
            if schedule['name'] == sched_type:
                return schedule

    def get_current_period(self, sched):
        cur_period = None
        prev_start = datetime.time(0,0,0)
        if not sched:
            return cur_period
        for p in sched['periods']:
            hour, minute = p['start'].split(':')
            start = datetime.time(int(hour), int(minute), 0)
            if self.now.time() > start and start > prev_start:
              cur_period = p
              prev_start = start
        return cur_period

    def load_schedule(self, source):
        """
        In order to make this slightly more general, we allow the source of the JSON-spec
        schedule to be specified as a URI. Mongo, HTTP and File URIs are supported, but
        we can easily imagine extending this to other databases or sources.
        """
        uri = urlparse.urlparse(source)
        scheme = uri.scheme.lower()
        if scheme == 'mongodb':
            from pymongo import MongoClient
            from pymongo.errors import ConnectionFailure as MongoConnectionFailure
            url, port = uri.netloc.split(':')
            db = uri.path[1:] # remove leading '/'
            MongoClient = MongoClient(url, int(port))
            MongoDatabase = getattr(MongoClient, db)
            self.master_schedule = MongoDatabase.master_schedule.find_one()
            self.schedules = MongoDatabase.schedules
        elif scheme == 'file':
            import json
            filename = uri.path[1:] # remove leading '/'
            sched = json.load(open(filename))
            self.master_schedule = sched['master_schedule']
            self.schedules = sched['schedules']
        elif scheme == 'http':
            import requests
            sched = json.loads(requests.get(source).content)
            self.master_schedule = sched['master_schedule']
            self.schedules = sched['schedules']
