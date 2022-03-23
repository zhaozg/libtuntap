/*
 * Copyright (c) 2012 Tristan Le Guern <tleguern@bouledef.eu>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/errno.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_utun.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

#include <fcntl.h>
#include <ifaddrs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tuntap.h"
#include "private.h"

#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/kern_event.h>

static int
tuntap_utun_open(char * ifname, uint32_t namesz, int num)
{
	int fd;
	struct sockaddr_ctl addr = { 0 };
	struct ctl_info info = { 0 };

	if (-1 == (fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL))) {
		tuntap_log(TUNTAP_LOG_ERR, "utun is not supported");
		return -1;
	}

	strncpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name));

	if (ioctl(fd, CTLIOCGINFO, &info) < 0) {
		tuntap_log(TUNTAP_LOG_ERR, "Can't retrieve kernel control id");
		tuntap_log(TUNTAP_LOG_ERR, strerror(errno));
		close(fd);
		return -1;
	}

	addr.sc_id = info.ctl_id;
	addr.sc_len = sizeof(addr);
	addr.sc_family = AF_SYSTEM;
	addr.ss_sysaddr = AF_SYS_CONTROL;
	addr.sc_unit = num + 1;   /* utunX where X is sc.sc_unit -1
		                     sc.sc_unit be 0 when TUNTAP_ID_ANY */

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		tuntap_log(TUNTAP_LOG_ERR, strerror(errno));
		tuntap_log(TUNTAP_LOG_ERR, "utun interface probably already in use");
		close(fd);
		return -1;
	}

	if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &namesz) < 0) {
		tuntap_log(TUNTAP_LOG_ERR, "Can't retrieve utun name");
		close(fd);
		return -1;
	}
	return fd;
}

int
tuntap_sys_start(struct device *dev, int mode, int tun) {
	char name[MAXPATHLEN];
	int fd;

	fd = -1;

	/* Force creation of the driver if needed or let it resilient */
	if (mode & TUNTAP_MODE_PERSIST) {
		tuntap_log(TUNTAP_LOG_NOTICE,
		    "Your system does not support persistent device");
		return -1;
	}

	if (mode == TUNTAP_MODE_ETHERNET) {
		tuntap_log(TUNTAP_LOG_NOTICE,
		    "Your system does not support tap device");
		return -1;
	}

        /* Check the mode: tun */
	if (mode != TUNTAP_MODE_TUNNEL) {
		tuntap_log(TUNTAP_LOG_ERR, "Invalid parameter 'mode'");
		return -1;
	}
	/* Check tun number */
	if (tun < 0 || tun > TUNTAP_ID_ANY) {
		tuntap_log(TUNTAP_LOG_ERR, "Invalid parameter 'unit'");
		return -1;
	}

	fd = tuntap_utun_open(name, IFNAMSIZ,
				(tun == TUNTAP_ID_ANY ? -1 : tun));
	if (fd != -1)
		strlcpy(dev->if_name, name, sizeof dev->if_name);

	/* Try to use the given driver or loop throught the avaible ones */
	switch (fd) {
	case -1:
		tuntap_log(TUNTAP_LOG_ERR, "Permission denied");
		return -1;
	case 256:
		tuntap_log(TUNTAP_LOG_ERR, "Can't find a tun entry");
		return -1;
	default:
		/* NOTREACHED */
		break;
	}

	return fd;
}

void
tuntap_sys_destroy(struct device *dev) {
    (void)dev;
}

int
tuntap_sys_set_hwaddr(struct device *dev, struct ether_addr *eth_addr) {
	struct ifreq ifr;

	(void)memset(&ifr, '\0', sizeof ifr);
	(void)strlcpy(ifr.ifr_name, dev->if_name, sizeof ifr.ifr_name);
	ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;
	ifr.ifr_addr.sa_family = AF_LINK;
	(void)memcpy(ifr.ifr_addr.sa_data, eth_addr, ETHER_ADDR_LEN);
	if (ioctl(dev->ctrl_sock, SIOCSIFLLADDR, &ifr) < 0) {
	        tuntap_log(TUNTAP_LOG_ERR, "Can't set link-layer address");
		return -1;
	}
	return 0;
}

int
tuntap_sys_set_ipv4(struct device *dev, t_tun_in_addr *s4, uint32_t bits) {
	struct ifaliasreq ifa;
	struct ifreq ifr;
	struct sockaddr_in addr;
	struct sockaddr_in mask;

	(void)memset(&ifa, '\0', sizeof ifa);
	(void)strlcpy(ifa.ifra_name, dev->if_name, sizeof ifa.ifra_name);

	(void)memset(&ifr, '\0', sizeof ifr);
	(void)strlcpy(ifr.ifr_name, dev->if_name, sizeof ifr.ifr_name);

	/* Delete previously assigned address */
	(void)ioctl(dev->ctrl_sock, SIOCDIFADDR, &ifr);

	/*
	 * Fill-in the destination address and netmask,
         * but don't care of the broadcast address
	 */
	(void)memset(&addr, '\0', sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = s4->s_addr;
	addr.sin_len = sizeof addr;
	(void)memcpy(&ifa.ifra_addr, &addr, sizeof addr);

	(void)memset(&mask, '\0', sizeof mask);
	mask.sin_family = AF_INET;
	mask.sin_addr.s_addr = bits;
	mask.sin_len = sizeof mask;
	(void)memcpy(&ifa.ifra_mask, &mask, sizeof ifa.ifra_mask);

	/* Simpler than calling SIOCSIFADDR and/or SIOCSIFBRDADDR */
	if (ioctl(dev->ctrl_sock, SIOCSIFADDR, &ifa) == -1) {
		tuntap_log(TUNTAP_LOG_ERR, "Can't set IP/netmask");
		return -1;
	}
	return 0;
}

int
tuntap_sys_set_descr(struct device *dev, const char *descr, size_t len) {
	tuntap_log(TUNTAP_LOG_NOTICE,
	    "Your system does not support tuntap_set_descr()");
	return -1;
}

char *
tuntap_sys_get_descr(struct device *dev) {
	(void)dev;
	tuntap_log(TUNTAP_LOG_NOTICE,
	    "Your system does not support tuntap_get_descr()");
	return NULL;
}
