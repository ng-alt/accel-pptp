# Copyright 1999-2006 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: /var/cvsroot/gentoo-x86/net-dialup/pptpd/pptpd-1.3.1.ebuild,v 1.1 2006/03/26 09:13:06 mrness Exp $

inherit linux-mod eutils autotools

DESCRIPTION="Linux Point-to-Point Tunnelling Protocol Client/Server"
SRC_URI="mirror://sourceforge/accel-pptp/accel-pptp-beta-0.6.tar.bz2"
HOMEPAGE="http://accel-pptp.sourceforge.net/"

SLOT="0"
LICENSE="GPL"
KEYWORDS="~amd64 ~x86"
IUSE="tcpd server"

S=${WORKDIR}/accel-pptp-beta-0.6

DEPEND=">=net-dialup/ppp-2.4.2
        >=virtual/linux-sources-2.6.15
	tcpd? ( sys-apps/tcp-wrappers )"
RDEPEND="virtual/modutils"

MODULE_NAMES="ppp_pptp(misc:${S}/ppp_pptp)"
BUILD_TARGETS="default"
BUILD_PARAMS="KDIR=${KERNEL_DIR}"
CONFIG_CHECK="PPP"
MODULESD_PPPPPTP_ALIASES="char-major-245 ppp_pptp"
MODULESD_PPPPPTP_EXAMPLES=("ppp_pptp min_window=5" "ppp_pptp max_window=100")


src_unpack() {
	unpack ${A}

	local PPPD_VER=`best_version net-dialup/ppp`
	PPPD_VER=${PPPD_VER#*/*-} #reduce it to ${PV}-${PR}
	PPPD_VER=${PPPD_VER%%[_-]*} # main version without beta/pre/patch/revision
	#Match pptpd-logwtmp.so's version with pppd's version (#89895)
	sed -i -e "s:\\(#define[ \\t]*VERSION[ \\t]*\\)\".*\":\\1\"${PPPD_VER}\":" "${S}/pptpd-1.3.1/plugins/patchlevel.h"
	sed -i -e "s:\\(#define[ \\t]*VERSION[ \\t]*\\)\".*\":\\1\"${PPPD_VER}\":" "${S}/pppd_plugin/src/pppd/patchlevel.h"
	
	convert_to_m ${S}/ppp_pptp/Makefile
}

src_compile() {
	
	if use server; then
	    cd ${S}/pptpd-1.3.1
	    eautoreconf

	    local myconf
	    use tcpd && myconf="--with-libwrap"
	    econf --with-bcrelay \
		${myconf} || die "configure failed"
	    emake COPTS="${CFLAGS}" || die "make failed"
	fi

	cd ${S}/pppd_plugin
	eautoreconf
	local myconf
	econf ${myconf} || die "configure failed"
	emake COPTS="${CFLAGS}" || die "make failed"
	
	cd ${S}/ppp_pptp
	linux-mod_src_compile || die "failed to build driver"
}

src_install () {
	if use server; then
	    cd ${S}/pptpd-1.3.1
	    einstall || die "make install failed"

	    insinto /etc
	    doins samples/pptpd.conf

	    insinto /etc/ppp
	    doins samples/options.pptpd

	    exeinto /etc/init.d
	    newexe "${FILESDIR}/pptpd-init" pptpd

	    insinto /etc/conf.d
	    newins "${FILESDIR}/pptpd-confd" pptpd
	fi
	
	cd ${S}/pppd_plugin/src/.libs
	local PPPD_VER=`best_version net-dialup/ppp`
	PPPD_VER=${PPPD_VER#*/*-} #reduce it to ${PV}-${PR}
	PPPD_VER=${PPPD_VER%%[_-]*} # main version without beta/pre/patch/revision
	insinto /usr/lib/pppd/${PPPD_VER}
	newins pptp.so.0.0.0 pptp.so

	cd ${S}/ppp_pptp
	linux-mod_src_install
	
	cd ${S}
        insinto /etc/modules.d
        newins  "${FILESDIR}/modules.d" pptp	    
	mknod /dev/pptp c 245 0 >& /dev/null
	
	cd ${S}
	dodoc README
	cp -R example "${D}/usr/share/doc/${P}/exmaple"
}

pkg_postinst () {
    modules-update
}
