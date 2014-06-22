all:
	c26
	c27

c26:
	/usr/bin/python2.6 /usr/bin/pycompile -V 2.6 pops.py && mv pops.pyc pops-2.6.pyc

c27:
	/usr/bin/python2.7 /usr/bin/pycompile -f -V2.7 pops.py && mv pops.pyc pops-2.7.pyc

clean:
	-rm *.pyc
	-rm *.pyo	
