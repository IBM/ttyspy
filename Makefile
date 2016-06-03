SHELL := /bin/bash

VERSION   := $(shell (git describe --exact-match || git describe --abbrev=0) 2>/dev/null | sed 's/^v//')
ITERATION := $(shell git describe --exact-match &>/dev/null && echo 1 || git describe | perl -pe's/^[^-]+-//;s/-/./')

all: client/ttyspy-client_$(VERSION)-$(ITERATION)_amd64.deb ttyspy-server_$(VERSION)-$(ITERATION)_amd64.deb

client/ttyspy-client_$(VERSION)-$(ITERATION)_amd64.deb: client/src/ttyspy
	cd client && fpm -t deb -s dir -a amd64 -v $(VERSION) --iteration $(ITERATION) \
		-d libcurl3 --deb-recommends perl -n ttyspy-client \
		src/ttyspy=/usr/bin/ttyspy src/ttyspyd=/usr/sbin/ttyspyd \
		ttyspy.conf=/etc/ttyspy.conf ../contrib/ssh-mosh-filter=/usr/bin/ssh-mosh-filter

client/src/ttyspy:
	cd client && autoreconf --install && ./configure
	$(MAKE) -C client

ttyspy-server_$(VERSION)-$(ITERATION)_amd64.deb: src/session_receiver/session_receiver
	fpm -t deb -s dir -a amd64 -v $(VERSION) --iteration $(ITERATION) \
		 -n ttyspy-server src/session_receiver/session_receiver=/usr/bin/ttyspy_receiver

src/session_receiver/session_receiver:
	cd src/session_receiver && go build

clean:
	rm -f src/session_receiver/session_receiver
	rm -f client/*.deb *.deb
	$(MAKE) -C client clean
