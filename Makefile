APXS=apxs
SOURCE=mod_authn_google.c base32.c hmac.c sha1.c
.FORCE: all
all: $(SOURCE)
	$(APXS) -c $^

install: all
	 sudo cp .libs/mod_authn_google.so /usr/local/apache2/modules/

clean:
	rm -rf .libs/ *.o *.so *.la *.slo *.lo

test:
	make install
	sleep 1
	sudo service httpd restart
	
