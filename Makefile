APXS=apxs
APACHECTL=apachectl

all: mod_web_bot_auth.so

mod_web_bot_auth.so: mod_web_bot_auth.c
	$(APXS) -c mod_web_bot_auth.c

clean:
	-rm -f mod_web_bot_auth.o mod_web_bot_auth.slo mod_web_bot_auth.so

install: all
	$(APXS) -i mod_web_bot_auth.so

restart:
	$(APACHECTL) restart
