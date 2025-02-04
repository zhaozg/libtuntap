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
#include <sys/sockio.h>
#include <sys/socket.h>
#include <sys/param.h> /* For MAXPATHLEN */

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_tun.h>
#include <net/if_tap.h>
#include <netinet/if_ether.h>

#include <fcntl.h>
#include <ifaddrs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tuntap.h"
#include "private.h"

static int
tuntap_sys_create_dev(struct device *dev, int mode, int tun) {
	struct ifreq ifr;
	char *name;

	if (mode == TUNTAP_MODE_ETHERNET)
		name = "tap%i";
	else
		name = "tun%i";

	/* At this point 'tun' can't be TUNTAP_ID_ANY */
	(void)memset(&ifr, '\0', sizeof ifr);
	(void)snprintf(ifr.ifr_name, IF_NAMESIZE, name, tun);

	if (ioctl(dev->ctrl_sock, SIOCIFCREATE, &ifr) == -1) {
		tuntap_log(TUNTAP_LOG_ERR, "Can't set persistent");
		return -1;
	}
	return 0;
}

/*
 * NetBSD support auto-clonning, but only for tap device.
 * To access /dev/tapN we have to create it before.
 */
static int
tuntap_sys_start_tap(struct device *dev, int tun) {
	int fd;
	struct ifreq ifr;
	struct ifaddrs *ifa;
	char name[IF_NAMESIZE + 5]; /* For /dev/IFNAMSIZ */

	fd = -1;
	(void)memset(&ifr, '\0', sizeof ifr);
	(void)memset(name, '\0', sizeof name);

	/* Set the device path to open */
	if (tun < TUNTAP_ID_MAX) {
		/* Create the wanted device */
		tuntap_sys_create_dev(dev, TUNTAP_MODE_ETHERNET, tun);
		(void)snprintf(name, sizeof name, "/dev/tap%i", tun);
	} else if (tun == TUNTAP_ID_ANY) {
		/* Or use autocloning */
		(void)memcpy(name, "/dev/tap", 8);
	} else {
		return -1;
	}

	if ((fd = open(name, O_RDWR)) == -1) {
		char buf[11 + MAXPATHLEN];

		(void)memset(buf, 0, sizeof buf);
		snprintf(buf, sizeof buf, "Can't open %s", name);
		tuntap_log(TUNTAP_LOG_DEBUG, buf);
		return -1;
	}

	/* Get the interface name */
	if (ioctl(fd, TAPGIFNAME, &ifr) == -1) {
		tuntap_log(TUNTAP_LOG_ERR, "Can't get interface name");
		return -1;
	}
	(void)strlcpy(dev->if_name, ifr.ifr_name, sizeof dev->if_name);

	/* Get the interface default values */
	if (ioctl(dev->ctrl_sock, SIOCGIFFLAGS, &ifr) == -1) {
		tuntap_log(TUNTAP_LOG_ERR, "Can't get interface values");
		return -1;
	}

	/* Save flags for tuntap_{up, down} */
	dev->flags = ifr.ifr_flags;

	/* Save pre-existing MAC address */
	if (getifaddrs(&ifa) == 0) {
		struct ifaddrs *pifa;

		for (pifa = ifa; pifa != NULL; pifa = pifa->ifa_next) {
			if (strcmp(pifa->ifa_name, dev->if_name) == 0) {
				struct ether_addr eth_addr;

				/*
				 * The MAC address is from 10 to 15.
				 *
				 * And yes, I know, the buffer is supposed
				 * to have a size of 14 bytes.
				 */
				(void)memcpy(dev->hwaddr,
				  pifa->ifa_addr->sa_data + 10,
				  ETHER_ADDR_LEN);

				(void)memset(&eth_addr.ether_addr_octet, 0,
				  ETHER_ADDR_LEN);
				(void)memcpy(&eth_addr.ether_addr_octet,
				  pifa->ifa_addr->sa_data + 10,
				  ETHER_ADDR_LEN);
				break;
			}
		}
		if (pifa == NULL)
			tuntap_log(TUNTAP_LOG_WARN,
			    "Can't get link-layer address");
		freeifaddrs(ifa);
	}
	return fd;
}

static int
tuntap_sys_start_tun(struct device *dev, int tun) {
	struct ifreq ifr;
	char name[MAXPATHLEN];
	int fd;

	/*
	 * Try to use the given driver, or loop throught the avaible ones
	 */
	fd = -1;
	if (tun < TUNTAP_ID_MAX) {
		(void)snprintf(name, sizeof name, "/dev/tun%i", tun);
		fd = open(name, O_RDWR);
	} else if (tun == TUNTAP_ID_ANY) {
		for (tun = 0; tun < TUNTAP_ID_MAX; ++tun) {
			(void)memset(name, '\0', sizeof name);
			(void)snprintf(name, sizeof name, "/dev/tun%i", tun);
			if ((fd = open(name, O_RDWR)) > 0)
				break;
		}
	} else {
		return -1;
	}
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

	/* Set the interface name */
	(void)memset(&ifr, '\0', sizeof ifr);
	(void)snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "tun%i", tun);
	/* And save it */
	(void)strlcpy(dev->if_name, ifr.ifr_name, sizeof dev->if_name);

	/* Get the interface default values */
	if (ioctl(dev->ctrl_sock, SIOCGIFFLAGS, &ifr) == -1) {
		tuntap_log(TUNTAP_LOG_ERR, "Can't get interface values");
		return -1;
	}

	/* Save flags for tuntap_{up, down} */
	dev->flags = ifr.ifr_flags;

	return fd;
}

int
tuntap_sys_start(struct device *dev, int mode, int tun) {
	int fd;

	/* Force creation of the driver if needed or let it resilient */
	if (mode & TUNTAP_MODE_PERSIST) {
		mode &= ~TUNTAP_MODE_PERSIST;
		if (tuntap_sys_create_dev(dev, mode, tun) == -1)
			return -1;
	}

        /* tun and tap devices are not created in the same way */
	if (mode == TUNTAP_MODE_ETHERNET) {
		fd = tuntap_sys_start_tap(dev, tun);
	}
	else if (mode == TUNTAP_MODE_TUNNEL) {
		fd = tuntap_sys_start_tun(dev, tun);
	}
	else {
		return -1;
	}

	return fd;
}

void
tuntap_sys_destroy(struct device *dev) {
	struct ifreq ifr;

	(void)memset(&ifr, '\0', sizeof ifr);
	(void)strlcpy(ifr.ifr_name, dev->if_name, sizeof ifr.ifr_name);

	if (ioctl(dev->ctrl_sock, SIOCIFDESTROY, &ifr) == -1)
		tuntap_log(TUNTAP_LOG_WARN, "Can't destroy the interface");
}

int
tuntap_sys_set_hwaddr(struct device *dev, struct ether_addr *eth_addr) {
	struct ifaliasreq ifra;

	(void)memset(&ifra, 0, sizeof ifra);
	(void)memcpy(ifra.ifra_name, dev->if_name, sizeof dev->if_name);
	ifra.ifra_addr.sa_len = ETHER_ADDR_LEN;
	ifra.ifra_addr.sa_family = AF_LINK;
	(void)memcpy(ifra.ifra_addr.sa_data, eth_addr, ETHER_ADDR_LEN);

	if (ioctl(dev->ctrl_sock, SIOCSIFPHYADDR, &ifra) == -1) {
	        tuntap_log(TUNTAP_LOG_ERR, "Can't set link-layer address");
		return -1;
	}
	return 0;
}

int
tuntap_sys_set_ipv4(struct device *dev, t_tun_in_addr *s, uint32_t bits) {
	struct ifaliasreq ifa;
	struct ifreq ifr;
	struct sockaddr_in mask;
	struct sockaddr_in addr;

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
	addr.sin_addr.s_addr = s->s_addr;
	addr.sin_len = sizeof addr;
	(void)memcpy(&ifa.ifra_addr, &addr, sizeof addr);

	(void)memset(&mask, '\0', sizeof mask);
	mask.sin_family = AF_INET;
	mask.sin_addr.s_addr = bits;
	mask.sin_len = sizeof mask;
	(void)memcpy(&ifa.ifra_mask, &mask, sizeof ifa.ifra_mask);

	/* Simpler than calling SIOCSIFADDR and/or SIOCSIFBRDADDR */
	if (ioctl(dev->ctrl_sock, SIOCAIFADDR, &ifa) == -1) {
		tuntap_log(TUNTAP_LOG_ERR, "Can't set IP/netmask");
		return -1;
	}
	return 0;
}

int
tuntap_sys_set_dstipv4(struct device *dev, t_tun_in_addr *s) {
	struct ifaliasreq ifa;
	struct sockaddr_in addr;

	(void)memset(&ifa, '\0', sizeof ifa);
	(void)strlcpy(ifa.ifra_name, dev->if_name, sizeof ifa.ifra_name);

	/*
	 * Fill-in the destination address and netmask,
         * but don't care of the broadcast address
	 */
	(void)memset(&addr, '\0', sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = s->s_addr;
	addr.sin_len = sizeof addr;
	(void)memcpy(&ifa.ifr_dstaddr, &addr, sizeof addr);

	if (ioctl(dev->ctrl_sock, SIOCSIFDSTADDR, &ifa) == -1) {
		tuntap_log(TUNTAP_LOG_ERR, "Can't set destination IP");
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
