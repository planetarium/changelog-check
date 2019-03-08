all: lib

devserver: devlib
	dev_appserver.py \
		--dev_appserver_log_level debug \
		--enable_host_checking false \
		app.yaml

ngrok: devlib
	ngrok http --host-header=rewrite 8080

clean:
	rm *.pyc
	rm -rf lib/

devlib: lib
	pip2.7 install -t lib/ -r dev-requirements.txt

lib: requirements.txt
	mkdir -p lib
	pip2.7 install -U -t lib/ -r requirements.txt
