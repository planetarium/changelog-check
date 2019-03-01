all: lib

devlib: lib
	pip2.7 install -t lib/ -r dev-requirements.txt

lib: requirements.txt
	mkdir -p lib
	pip2.7 install -U -t lib/ -r requirements.txt
