#!/usr/bin/python
import serial
import os
import sys
import time

class USB300(object):

    def proccrc8(self, CRC, u8Data): 
        return self.u8CRC8Table[(CRC ^ u8Data) & 0xff]; 
            
    def printHeader(self):
        print("Header:",int(self.dataLength,16),int(self.opDataLength,16),int(self.packetType,16),self.headerCRC)
        return

    def printSerialData(self):
        return self.serialData[0:int(self.dataLength,16)*2]

    def printPacketType1(self):
        strRorg = "RORG: "
        strRorg += self.serialData[0:2]
            
        strData = "Data: "
        if strRorg[len(strRorg)-2:len(strRorg)] == 'f6':
            strData += self.serialData[2:4]
            strSrcId = "Source ID: "
            strSrcId += self.serialData[4:12]
            print strSrcId
                
        elif strRorg[len(strRorg)-2:len(strRorg)] == 'a5':
            strData += self.serialData[2:10]
            strSrcId = "Source ID: "
            strSrcId += self.serialData[10:18]
            print strSrcId
        else:
            pass
        print strData + "\n"
        return

    def printOpData():
        return

    def checkHeaderCRC(self):
        u8CRCHeader = 0
            
        u8CRCHeader = ( self.proccrc8(u8CRCHeader, int(self.dataLength,16)>>8))
        u8CRCHeader = ( self.proccrc8(u8CRCHeader, int(self.dataLength,16)&0xff))
        u8CRCHeader = ( self.proccrc8(u8CRCHeader, int(self.opDataLength,16)))
        u8CRCHeader = ( self.proccrc8(u8CRCHeader, int(self.packetType,16)))

        return (u8CRCHeader == int(self.headerCRC,16))

    def checkDataCRC(self):
        u8CRCData = 0
        i = 0

        while (i<len(self.serialData)-2):
            u8CRCData = self.proccrc8(u8CRCData, (int(self.serialData[i]+self.serialData[i+1],16)&0xff))
            i=i+2
        
        return (u8CRCData == int(self.serialData[len(self.serialData)-2]+self.serialData[len(self.serialData)-1],16))
                    
    def checkPacketType(self, x):
        return (self.packetType == x) #x is 'x'
    
    def checkSerialBuffer(self):
        return (self.ser.inWaiting() > 0)

    def getSerialData(self):
        #global dataLength, opDataLength, packetType, headerCRC,totalDataLength, serialData   
        s = 0
        i = 0
        while s != '55':
            if self.ser.inWaiting() != 0: 
                s = self.ser.read(1).encode("hex")
        
        while self.ser.inWaiting() < 5:  
            pass

        self.dataLength = self.ser.read(2).encode("hex") #read length field
        self.opDataLength = self.ser.read(1).encode("hex") #read op length field
        self.packetType = self.ser.read(1).encode("hex") #read packet type field
        self.headerCRC = self.ser.read(1).encode("hex") #read header crc field

        if (self.checkHeaderCRC()):  
            totalDataLength = (int(self.dataLength,16) + int(self.opDataLength,16))
 
            while self.ser.inWaiting() < totalDataLength:  
                pass 
                        
            self.serialData = self.ser.read(totalDataLength+1).encode("hex")  
            if self.checkDataCRC(): 
                return self.serialData       
            return "Data CRC Failed"
        return "Header CRC Failed"
            
    def calcESP3HeaderCRC(self,telegramHeader):
        u8CRC = 0;
        u8CRC = self.proccrc8(u8CRC,telegramHeader[1])
        u8CRC = self.proccrc8(u8CRC,telegramHeader[2])
        u8CRC = self.proccrc8(u8CRC,telegramHeader[3])
        u8CRC = self.proccrc8(u8CRC,telegramHeader[4])
        return u8CRC
            
    def calcESP3DataCRC(self,telegramData):
        u8CRC = 0;
        for index in range(len(telegramData)):
            u8CRC = self.proccrc8(u8CRC,telegramData[index])

        return u8CRC


    def calcESP3Header(self,packetType,packetData, *arg): # assumes 0 optional data
        pHeader = [0x55] #sync
        # for now we support max of 255 byte packets
        pHeader.append(0x00) #MSB Data Length
        pHeader.append(len(packetData)) #LSB Data Length
        if len(arg) == 0:
            pHeader.append(0x00) #optional data length
        else:
            pHeader.append(0x07)
        pHeader.append(packetType) #packet type
        pHeader.append(self.calcESP3HeaderCRC(pHeader)) # Header CRC
        return pHeader
                    
    def sendESP3Packet(self, packetType, packetData):
        pESP3Packet = calcESP3Header(packetType,packetData)
        pESP3Packet += packetData 
        pESP3Packet.append(calcESP3DataCRC(packetData))
        
        for index in range(len(pESP3Packet)):
            pESP3Packet[index] = chr(pESP3Packet[index])
            #byte by byte tx
            self.ser.write(pESP3Packet[index])                           
        return getSerialData()          

    def sendTest(self):
        self.ser.write("\x55\x00\x07\x00\x01\x11\xD5\x55\x00\x00\x00\x00\x80\x5A")

    def txRadio_LRN_RPS_F6_02_02_RockerA(self):
        for x in range(0, 3):         
            tx_eep_rockerAI(self.txId)
            sleep(.150) #based on maturity time and execution speed...
            tx_eep_rockerNoTab(self.txId)
            sleep(.050)
        return
     
    def tx_eep_rockerAI(self):
        self.txRadio_RPS('10', '30')
        return

    def tx_eep_rockerAO(self):
        self.txRadio_RPS('30', '30')
        return

    def tx_eep_rockerNoTab(self):               
        self.txRadio_RPS('00', '20')
        return

    def tx_terralux_learn(self):
        self.txRadio_4BS('ff','00','00','ff','30')
        return

    def tx_terralux_off(self):
        self.txRadio_4BS('30','00','00','00','30')
        return

    def tx_terralux_on(self):
        self.txRadio_4BS('31','00','00','00','30')
        return

    def tx_terralux_set_level(self, level):
        msb =  hex((level & 0xff00) >> 8)
        lsb =  hex((level & 0x00ff))
        self.txRadio_4BS('10',str(msb[2:len(msb)]),str(lsb[2:len(lsb)]),'00','30')
        return

    def tx_terralux_set_xmit_interval_1s(self):
        self.txRadio_4BS('03','01','00','00','30')
        return

    def link_plug_load_controller(self):
        self.tx_eep_rockerAI()
        time.sleep(0.1)
        self.tx_eep_rockerAI()
        time.sleep(0.1)
        self.tx_eep_rockerAI()

    def txRadio_RPS(self, txData, txStatus):
        return self.sendESP3Packet(0x01,[0xf6, #rorg
            int(txData[0:2],16), #radio data
            int(self.txId[0:2],16), int(self.txId[2:4],16), int(self.txId[4:6],16), int(self.txId[6:8],16), #sender id
            int(txStatus[0:2],16)]) #status

    def txRadio_4BS(self, txData1, txData2, txData3, txData4, txStatus):
        return self.sendESP3Packet(0x01,[0xa5, #4BS
            int(txData1[0:2],16), int(txData2[0:2],16),int(txData3[0:2],16),int(txData4[0:2],16),#radio data
            int(self.txId[0:2],16), int(self.txId[2:4],16), int(self.txId[4:6],16), int(self.txId[6:8],16), #sender id
            int(txStatus[0:2],16)],
            [0x00, int(self.destId[0:2],16), 
              int(self.destId[2:4],16), 
              int(self.destId[4:6],16), 
              int(self.destId[6:8],16), 0xff, 0x00]) #optional parameters and dest_id

    def sendESP3Packet(self,packetType, packetData, *args):
                    
        optData = [0x00, int(self.destId[0:2],16), int(self.destId[2:4],16), int(self.destId[4:6],16), int(self.destId[6:8],16),0xff,0x00]

        if len(args) == 0:
            pESP3Packet = self.calcESP3Header(packetType,packetData)
            pESP3Packet += packetData
            pESP3Packet.append(self.calcESP3DataCRC(packetData))
        elif len(args) == 1:
            optData = args[0]
            pESP3Packet = self.calcESP3Header(packetType,packetData, optData)                          
            pESP3Packet += packetData
            pESP3Packet += optData
            pESP3Packet.append(self.calcESP3DataCRC(packetData+optData))

        for index in range(len(pESP3Packet)):
            pESP3Packet[index] = chr(pESP3Packet[index])
            #byte by byte tx
            self.ser.write(pESP3Packet[index])                                                 

        return self.getSerialData()   

    def __init__(self, serial_port='/dev/ttyUSB0', usb_id='ffe14000', baud_rate=57600, dest_id='0187cd7b'):
        
        self.ser = serial.Serial(serial_port, baud_rate, timeout = 0)  # open serial port
        self.txId = usb_id
        self.destId = dest_id

        #global dataLength, opDataLength, packetType, headerCRC,totalDataLength, serialData
        
        self.u8CRC8Table = [
                              0x00, 0x07, 0x0e, 0x09, 0x1c, 0x1b, 0x12, 0x15, 
                              0x38, 0x3f, 0x36, 0x31, 0x24, 0x23, 0x2a, 0x2d, 
                              0x70, 0x77, 0x7e, 0x79, 0x6c, 0x6b, 0x62, 0x65, 
                              0x48, 0x4f, 0x46, 0x41, 0x54, 0x53, 0x5a, 0x5d, 
                              0xe0, 0xe7, 0xee, 0xe9, 0xfc, 0xfb, 0xf2, 0xf5, 
                              0xd8, 0xdf, 0xd6, 0xd1, 0xc4, 0xc3, 0xca, 0xcd, 
                              0x90, 0x97, 0x9e, 0x99, 0x8c, 0x8b, 0x82, 0x85, 
                              0xa8, 0xaf, 0xa6, 0xa1, 0xb4, 0xb3, 0xba, 0xbd, 
                              0xc7, 0xc0, 0xc9, 0xce, 0xdb, 0xdc, 0xd5, 0xd2, 
                              0xff, 0xf8, 0xf1, 0xf6, 0xe3, 0xe4, 0xed, 0xea, 
                              0xb7, 0xb0, 0xb9, 0xbe, 0xab, 0xac, 0xa5, 0xa2, 
                              0x8f, 0x88, 0x81, 0x86, 0x93, 0x94, 0x9d, 0x9a, 
                              0x27, 0x20, 0x29, 0x2e, 0x3b, 0x3c, 0x35, 0x32, 
                              0x1f, 0x18, 0x11, 0x16, 0x03, 0x04, 0x0d, 0x0a, 
                              0x57, 0x50, 0x59, 0x5e, 0x4b, 0x4c, 0x45, 0x42, 
                              0x6f, 0x68, 0x61, 0x66, 0x73, 0x74, 0x7d, 0x7a, 
                              0x89, 0x8e, 0x87, 0x80, 0x95, 0x92, 0x9b, 0x9c, 
                              0xb1, 0xb6, 0xbf, 0xb8, 0xad, 0xaa, 0xa3, 0xa4, 
                              0xf9, 0xfe, 0xf7, 0xf0, 0xe5, 0xe2, 0xeb, 0xec, 
                              0xc1, 0xc6, 0xcf, 0xc8, 0xdd, 0xda, 0xd3, 0xd4, 
                              0x69, 0x6e, 0x67, 0x60, 0x75, 0x72, 0x7b, 0x7c, 
                              0x51, 0x56, 0x5f, 0x58, 0x4d, 0x4a, 0x43, 0x44, 
                              0x19, 0x1e, 0x17, 0x10, 0x05, 0x02, 0x0b, 0x0c, 
                              0x21, 0x26, 0x2f, 0x28, 0x3d, 0x3a, 0x33, 0x34, 
                              0x4e, 0x49, 0x40, 0x47, 0x52, 0x55, 0x5c, 0x5b, 
                              0x76, 0x71, 0x78, 0x7f, 0x6A, 0x6d, 0x64, 0x63, 
                              0x3e, 0x39, 0x30, 0x37, 0x22, 0x25, 0x2c, 0x2b, 
                              0x06, 0x01, 0x08, 0x0f, 0x1a, 0x1d, 0x14, 0x13, 
                              0xae, 0xa9, 0xa0, 0xa7, 0xb2, 0xb5, 0xbc, 0xbb, 
                              0x96, 0x91, 0x98, 0x9f, 0x8a, 0x8D, 0x84, 0x83, 
                              0xde, 0xd9, 0xd0, 0xd7, 0xc2, 0xc5, 0xcc, 0xcb, 
                              0xe6, 0xe1, 0xe8, 0xef, 0xfa, 0xfd, 0xf4, 0xf3
                            ]
