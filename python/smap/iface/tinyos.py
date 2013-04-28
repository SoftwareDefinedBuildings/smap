"""
Copyright (c) 2013 Regents of the University of California
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions 
are met:

 - Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
 - Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the
   distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL 
THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED 
OF THE POSSIBILITY OF SUCH DAMAGE.
"""
"""
Provide twisted support for TinyOS serial forwarders.  You should
subclass TOSSerialClient and implement packetReceived.  You can then
connect it to a transport, for instance a serial port, using:

from twisted.internet.serialport import SerialPort
SerialPort(KetiMoteReceiver(self), port, reactor, baudrate=baud)

Based on Razvan Musaloiu-E.'s tos.py

@author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
"""

import logging

from twisted.internet import reactor, protocol

class TOSSerialClient(protocol.Protocol):
    HDLC_FLAG_BYTE = 0x7e
    HDLC_CTLESC_BYTE = 0x7d
    DEBUG = None

    def __init__(self):
        self.packet = []

    def dataReceived(self, data):
        self._pump(data)

    def _pump(self, data):
        # Developer notes:
        #
        # Packet data read from Serial is in this format:
        # [HDLC_FLAG_BYTE][Escaped data][HDLC_FLAG_BYTE]
        #
        # [Escaped data] is encoded so that [HDLC_FLAG_BYTE] byte
        # values cannot occur within it. When [Escaped data] has been
        # unescaped, the last 2 bytes are a 16-bit CRC of the earlier
        # part of the packet (excluding the initial HDLC_FLAG_BYTE
        # byte)
        #
        # It's also possible that the serial device was half-way
        # through transmitting a packet when this function was called
        # (app was just started). So we also neeed to handle this case:
        #
        # [Incomplete escaped data][HDLC_FLAG_BYTE][HDLC_FLAG_BYTE][Escaped data][HDLC_FLAG_BYTE]
        #
        # In this case we skip over the first (incomplete) packet.
        #

        # Read bytes until we get to a HDLC_FLAG_BYTE value
        # (either the end of a packet, or the start of a new one)
        for d in data:
            if ord(d) == self.HDLC_FLAG_BYTE:
                self._deliver()
            else:
                self.packet.append(ord(d))
            
    def _deliver(self):
        # Decode the packet, and check CRC:
        packet = self._unescape(self.packet)
        self.packet = []

        crc = self._crc16(0, packet[:-2])
        packet_crc = self._decode(packet[-2:])

        if crc != packet_crc:
            print ("wrong CRC: %x != %x %s (%s)" % \
                  (crc, packet_crc, ["%2x" % i for i in packet], str(self.DEBUG)))
            return

        if len(packet):
            self.packetReceived(''.join(map(chr, packet[:-2])))

    def _unescape(self, packet):
        r = []
        esc = False
        for b in packet:
            if esc:
                r.append(b ^ 0x20)
                esc = False
            elif b == self.HDLC_CTLESC_BYTE:
                esc = True
            else:
                r.append(b)
        return r

    def _decode(self, v):
        r = long(0)
        for i in v[::-1]:
            r = (r << 8) + i
        return r

    def _crc16(self, base_crc, frame_data):
        crc = base_crc
        for b in frame_data:
            crc = crc ^ (b << 8)
            for i in range(0, 8):
                if crc & 0x8000 == 0x8000:
                    crc = (crc << 1) ^ 0x1021
                else:
                    crc = crc << 1
                crc = crc & 0xffff
        return crc

