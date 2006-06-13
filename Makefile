default:
	echo Building kernel module
	(cd ppp_pptp; make )
	echo
	echo Building pppd plugin
	(cd pppd_plugin; ./configure && make)
	echo
	echo Building pptpd
	(cd pptpd-1.3.1; ./configure --prefix=/usr && make)

PPPD := $(shell cd /usr/lib/pppd; ls)
install_client: default
	if [ -z "$(PPPD)" ]; then echo pppd not found; exit -1; fi
	install -m 0644 pppd_plugin/src/.libs/pptp.so.0.0.0 /usr/lib/pppd/$(PPPD)/pptp.so
	(cd ppp_pptp; make install)
	if [ ! -c /dev/pptp ]; then mknod /dev/pptp c 245 0; fi

install_server: install_client
	(cd pptpd-1.3.1; make install)

clean:
	(cd ppp_pptp; make clean)
	(cd pppd_plugin; make clean)
	(cd pptpd-1.3.1; make clean)
distclean:
	(cd ppp_pptp; make clean)
	(cd pppd_plugin; make distclean)
	(cd pptpd-1.3.1; make distclean)
