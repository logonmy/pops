all:
	pycompile -O -f -V2.7 pops.py && mv pops.pyc pops-2.7.pyc

clean:
	-rm *.pyc
	-rm *.pyo	
