OBJS = TCPModbusClient.o DieWithError.o crc16.o utility.o
TRG = TCPModbusClient.py
MODULE = TCPModbusClient
CFILES = crc16.c DieWithError.c TCPModbusClient.c TCPModbusServer.c utility.c HandleModbusTCPClient.c
HFILES = TCPModbusClient.h
CC = gcc
LD = ld
DEBUG = -g
CFLAGS = -Wall -c $(DEBUG)

# need to build swig files special on Darwin
UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	LFLAGS = -bundle -flat_namespace -undefined suppress -lcrt1.o 
else
	LFLAGS = -shared
endif

all : $(TRG)

clean:
	rm -f *.o $(TRG) *_wrap.c TCPModbusClient.py *.so *.pyc

TCPModbusClient.py: TCPModbusClient.i $(CFILES) $(HFILES)
	swig -python $(MODULE).i
	$(CC) $(CFLAGS) $(CFILES) $(MODULE)_wrap.c -I/usr/lib/python2.6 -I/usr/include/python2.6
	$(LD) $(LFLAGS) -o _$(MODULE).so $(MODULE)_wrap.o $(OBJS)

utility.o : utility.c
	$(CC) $(CFLAGS) utility.c
