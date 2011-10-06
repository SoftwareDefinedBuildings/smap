
import sys
import os
import threading
import logging
import time
import socket

from twisted.internet.protocol import DatagramProtocol

# twisted doesn't support ipv6... this patches the reactor to add
# listenUDP6 and listenTCP6 methods.  It's not great, but it's a
# workaround that we can use and is easy to deploy (doesn't involve
# patching the twisted installation directory)
from tx.ipv6.internet import reactor

from smap.driver import SmapDriver
from smap.drivers.acmex2 import ACmeX2Report

class ACmeX2Driver(SmapDriver, DatagramProtocol):
    def datagramReceived(self, data, addr):
        rpt = ACmeX2Report.AcReport(data=data, data_length=len(data))
        moteid = addr[0].split('::')[1]
        if not moteid in self.ids:
            self.ids[moteid] = True
            self.add_timeseries('/' + moteid + '/true_power', 'mW', buffersz=2)
            self.add_timeseries('/' + moteid + '/apparent_power', 'mVA', buffersz=2)
            self.add_timeseries('/' + moteid + '/true_energy', 'mWh', buffersz=2)
            self.set_metadata('/' + moteid, {
                'Instrument/PartNumber' : moteid,
                'Instrument/SerialNumber' : ':'.join(['%02x' % x for x in rpt.get_eui64()]),
                'Instrument/SamplingPeriod' : str(rpt.get_period ()),
                })
        for idx in range(0,2):
            readingTime = rpt.get_globalTime() - (rpt.get_period() * (1 - idx))
            self._add('/' + moteid + '/true_energy', readingTime,
                      rpt.get_readings_cumulativeRealEnergy()[idx],
                      rpt.get_seq())
            self._add('/' + moteid + '/true_power', readingTime,
                      rpt.get_readings_averageRealPower()[idx],
                      rpt.get_seq())
            self._add('/' + moteid + '/apparent_power', readingTime,
                      rpt.get_readings_averageApparentPower()[idx],
                      rpt.get_seq())

    def setup(self, opts):
        self.port = int(opts.get('Port', 7002))
        self.ids = {}
        self.set_metadata('/', {
            'Extra/Driver' : 'smap.driver.acmex2.acmex2.ACmeX2Driver',
            'Instrument/Manufacturer': 'UC Berkeley',
            'Instrument/Model' : 'ACme X2',
            })

    def start(self):
        reactor.listenUDP6(self.port, self)
