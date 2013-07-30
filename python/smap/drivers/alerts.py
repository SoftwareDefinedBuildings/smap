import smtplib
import time

from smap.archiver.client import SmapClient
from smap.driver import SmapDriver
from smap.util import periodicSequentialCall

from twisted.internet import reactor

class Alert(SmapDriver):

  def setup(self, opts):
    url = opts.get('url', 'http://new.openbms.org/backend') 
    self.client = SmapClient(url)
    self.limit = float(opts.get('limit', 300)) # Seconds
    self.rate = float(opts.get('rate', 300))
    self.alert_interval = float(opts.get('alert_interval', 86400)) # Minimum seconds between alerts
    smtp_server = opts.get('smtp_server')
    self.server = smtplib.SMTP(smtp_server, 587)
    self.server.starttls()
    self.email = opts.get('email_address')
    pw = opts.get('password')
    self.server.login(self.email, pw)
    self.restrict = opts.get('restrict')
    self.recipient = opts.get('recipient')
    self.carrier = opts.get('carrier')

  def start(self):
    self.process = periodicSequentialCall(self.read)
    self.process.start(self.rate)

  def read(self):
    data = self.client.latest(self.restrict, streamlimit=-1)
    for d in data:
      uuid = d["uuid"]
      latest = d["Readings"][0][0] / 1000
      now = time.time()
      gap = now - latest
      if gap > self.limit:
        self.alert(uuid)
        self.process.stop()
        reactor.callLater(self.alert_interval, self.start)
        break 

  def alert(self, uuid):
    message = '\nGap of more than %s seconds in data for %s: uuid=%s' % (self.limit, self.restrict, uuid)
    print message
    self.server.sendmail(self.email, "%s@%s" % (self.recipient, self.carrier), message)
    self.process.stop()
