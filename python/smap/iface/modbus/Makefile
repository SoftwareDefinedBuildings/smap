
module:
	swig -python TCPModbusClient.i
	python setup.py build_ext
	mv `find build -name '*.so'` .

clean:
	rm -rf TCPModbusClient_wrap.c *.so TCPModbusClient.py build
