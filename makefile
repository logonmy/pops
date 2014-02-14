all:
	c26
	c27

c26:
	pycompile -V2.6 pops.py && mv pops.pyc pops-2.6.pyc

c27:
	pycompile -O -f -V2.7 pops.py && mv pops.pyc pops-2.7.pyc

clean:
	-rm *.pyc
	-rm *.pyo	
