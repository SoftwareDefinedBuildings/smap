
from distutils.core import setup, Extension

modbus_module = Extension('smap.iface.modbus._TCPModbusClient',
                          sources=["TCPModbusClient_wrap.c", "TCPModbusClient.c",
                                   "utility.c", "crc16.c", "DieWithError.c",
                                   "HandleModbusTCPClient.c"])

setup (name='modbus', 
       version='0.1',
       author='Stephen Dawson-Haggerty',
       ext_modules=[modbus_module],
       py_modules="TCPModbusClient")
