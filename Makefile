APACHE_CONFIG=/etc/httpd
APACHE_BIN=/usr/sbin/httpd
APXS=apxs
PWD=$(shell pwd)
AXPS_FLAGS=-Wc,-fdump-rtl-expand
SOURCE=mod_authn_google.c base32.c hmac.c sha1.c
.FORCE: all
all: $(SOURCE)
	$(APXS) $(AXPS_FLAGS) -c $^

make32: $(SOURCE)
	$(APXS) -Wc,-m32 -c $^

install: all
	 sudo cp .libs/mod_authn_google.so /etc/httpd/modules/

clean:
	rm -rf .libs/ *.o *.so *.la *.slo *.lo *.expand

debug: $(SOURCE)
	$(APXS) -D DEBUG=1 -c $^

test:
	make install
	sleep 1
	if [ ! -f ${APACHE_CONFIG}/ga_auth/test ]  ; then  \
		sudo mkdir -p ${APACHE_CONFIG}/ga_auth/ ; \
		sudo cp test.gaconf ${APACHE_CONFIG}/ga_auth/test ; \
	fi
	
	sudo ${APACHE_BIN} -e debug -X -f $(PWD)/httpd.conf &
	sudo tail -f /var/log/httpd/error_log
	


