PPPD := $(shell /usr/sbin/pppd --version 2>&1 | grep version)
PPPD := $(patsubst pppd,,$(PPPD))
PPPD := $(patsubst version,,$(PPPD))
PPPD := $(strip $(PPPD))

default:
	if [ -z "$(PPPD)" ]; then echo pppd not found; exit -1; fi
	echo Building kernel module
	(cd kernel/driver; make )
	echo
	echo Building pppd plugin
	sed -i -e "s:\\(#define[ \\t]*PPP_VERSION[ \\t]*\\)\".*\":\\1\"$(PPPD)\":" "pppd_plugin/src/pppd/patchlevel.h"
	(cd pppd_plugin; ./configure && make)
	echo
	echo Building pptpd
	sed -i -e "s:\\(#define[ \\t]*VERSION[ \\t]*\\)\".*\":\\1\"$(PPPD)\":" "pptpd-1.3.3/plugins/patchlevel.h"
	(cd pptpd-1.3.3; ./configure --prefix=/usr && make)

client_install: default
	install -m 0644 pppd_plugin/src/.libs/pptp.so.0.0.0 /usr/lib/pppd/$(PPPD)/pptp.so
	(cd kernel/driver; make install)

server_install: client_install
	(cd pptpd-1.3.3; make install)

clean:
	(cd kernel/driver; make clean)
	(cd pppd_plugin; make clean)
	(cd pptpd-1.3.3; make clean)
distclean:
	(cd kernel/driver; make clean)
	(cd pppd_plugin; make distclean)
	(cd pptpd-1.3.3; make distclean)
