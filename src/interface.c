/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 */

#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <unistd.h>

#include "mdns.h"

/**
 * netlink_recv_cb() - netlink receive callback invoked by uloop
 * @ufd: uloop file descriptor
 * @events: event flags
 *
 * Processes netlink messages for interface and address changes,
 * invokes ucode callbacks for relevant events.
 */
static void netlink_recv_cb(struct uloop_fd *ufd, unsigned int events)
{
	char buf[8192];
	struct sockaddr_nl sa;
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = sizeof(buf)
	};
	/* Designated members only: musl pads struct msghdr on 64-bit, so a
	 * positional initialiser assigns msg_control to the padding */
	struct msghdr msg = {
		.msg_name = &sa,
		.msg_namelen = sizeof(sa),
		.msg_iov = &iov,
		.msg_iovlen = 1
	};
	struct nlmsghdr *nh;
	ssize_t len;

	len = recvmsg(ufd->fd, &msg, 0);
	if (len < 0)
		return;

	/* len stays signed: NLMSG_NEXT subtracts the aligned length, which can
	 * exceed the length NLMSG_OK validated, and the guard that catches that
	 * is a >= sizeof() test that an unsigned cast defeats */
	for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
		struct ifinfomsg *ifi;
		struct ifaddrmsg *ifa;
		struct mdns_interface *iface;
		char ifname[IF_NAMESIZE];

		if (nh->nlmsg_type == NLMSG_DONE)
			break;

		if (nh->nlmsg_type == NLMSG_ERROR)
			break;

		switch (nh->nlmsg_type) {
		case RTM_NEWLINK:
			ifi = NLMSG_DATA(nh);
			if (!if_indextoname(ifi->ifi_index, ifname))
				break;
			iface = mdns_interface_get(ifname);
			if (iface) {
				/* Interface came up or changed */
				if (ifi->ifi_flags & IFF_UP) {
					/* A socket joined the group on the old index
					 * receives nothing once the index changes */
					if (iface->ifindex != ifi->ifi_index) {
						mdns_interface_disable(iface);
						iface->ifindex = ifi->ifi_index;
					}

					mdns_interface_enable(iface, iface->want_ipv4,
							      iface->want_ipv6);
					mdns_callback_interface_change(iface, MDNS_IFACE_UP);
				}
			}
			break;

		case RTM_DELLINK:
			ifi = NLMSG_DATA(nh);
			if (!if_indextoname(ifi->ifi_index, ifname))
				break;
			iface = mdns_interface_get(ifname);
			if (iface) {
				mdns_interface_disable(iface);
				mdns_callback_interface_change(iface, MDNS_IFACE_DOWN);
			}
			break;

		case RTM_NEWADDR:
			ifa = NLMSG_DATA(nh);
			if (!if_indextoname(ifa->ifa_index, ifname))
				break;
			iface = mdns_interface_get(ifname);
			if (iface) {
				mdns_interface_update_addrs(iface);
				mdns_interface_enable(iface, iface->want_ipv4,
						      iface->want_ipv6);
				mdns_callback_interface_change(iface, MDNS_IFACE_ADDR_ADD);
			}
			break;

		case RTM_DELADDR:
			ifa = NLMSG_DATA(nh);
			if (!if_indextoname(ifa->ifa_index, ifname))
				break;
			iface = mdns_interface_get(ifname);
			if (iface) {
				mdns_interface_update_addrs(iface);
				mdns_callback_interface_change(iface, MDNS_IFACE_ADDR_DEL);
			}
			break;

		default:
			break;
		}
	}
}

/**
 * mdns_interface_init() - initialise interface monitoring subsystem
 *
 * Creates netlink socket, subscribes to link and address changes,
 * registers with uloop.
 *
 * Return: 0 on success, -1 on error
 */
int mdns_interface_init(void)
{
	struct sockaddr_nl sa;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
	if (fd < 0) {
		mdns_set_error("Failed to create netlink socket");
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;

	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		mdns_set_error("Failed to bind netlink socket");
		close(fd);
		return -1;
	}

	ctx.netlink_fd.fd = fd;
	ctx.netlink_fd.cb = netlink_recv_cb;
	uloop_fd_add(&ctx.netlink_fd, ULOOP_READ);

	return 0;
}

/**
 * mdns_interface_cleanup() - shutdown interface monitoring
 *
 * Destroys all interfaces, closes netlink socket.
 */
void mdns_interface_cleanup(void)
{
	struct mdns_interface *iface, *tmp;

	avl_for_each_element_safe(&ctx.interfaces, iface, node, tmp) {
		mdns_interface_destroy(iface);
	}

	if (ctx.netlink_fd.fd >= 0) {
		uloop_fd_delete(&ctx.netlink_fd);
		close(ctx.netlink_fd.fd);
		ctx.netlink_fd.fd = -1;
	}
}

/**
 * mdns_interface_create() - create interface object
 * @name: interface name
 *
 * Allocates interface structure, resolves interface index,
 * adds to global AVL tree.
 *
 * Return: pointer to interface, or NULL on error
 */
struct mdns_interface *mdns_interface_create(const char *name)
{
	struct mdns_interface *iface;

	iface = calloc(1, sizeof(*iface));
	if (!iface)
		return NULL;

	iface->name = strdup(name);
	if (!iface->name) {
		free(iface);
		mdns_set_error("Out of memory");
		return NULL;
	}

	iface->ifindex = if_nametoindex(name);
	iface->node.key = iface->name;

	for (int i = 0; i < MDNS_SOCKET_MAX; i++)
		iface->sockets[i].fd = -1;

	avl_insert(&ctx.interfaces, &iface->node);

	return iface;
}

/**
 * mdns_interface_destroy() - destroy interface object
 * @iface: interface to destroy
 *
 * Disables sockets, frees addresses, removes from tree, releases memory.
 */
void mdns_interface_destroy(struct mdns_interface *iface)
{
	if (!iface)
		return;

	packet_queue_purge(iface);
	mdns_interface_disable(iface);
	avl_delete(&ctx.interfaces, &iface->node);

	free(iface->name);
	free(iface->ipv4.addrs);
	free(iface->ipv4.netmasks);
	free(iface->ipv6.addrs);
	free(iface->ipv6.prefixlens);
	free(iface);
}

/**
 * mdns_interface_get() - lookup interface by name
 * @name: interface name
 *
 * Return: pointer to interface, or NULL if not found
 */
struct mdns_interface *mdns_interface_get(const char *name)
{
	struct mdns_interface *iface;

	return avl_find_element(&ctx.interfaces, name, iface, node);
}

/**
 * mdns_interface_enable() - enable mDNS on interface
 * @iface: interface to enable
 * @ipv4: enable IPv4 sockets
 * @ipv6: enable IPv6 sockets
 *
 * Updates address list, opens requested sockets. Safe to call again after
 * the link or an address appears; sockets already open are left alone and
 * only the ones this call opened are closed if a later step fails.
 *
 * Return: 0 on success, -1 on error
 */
int mdns_interface_enable(struct mdns_interface *iface, bool ipv4, bool ipv6)
{
	bool opened_ipv4 = false;

	if (!iface)
		return -1;

	iface->want_ipv4 = ipv4;
	iface->want_ipv6 = ipv6;

	/* Update addresses first */
	mdns_interface_update_addrs(iface);

	/* Open IPv4 socket if requested and addresses available */
	if (ipv4 && iface->ipv4.count > 0 && iface->sockets[MDNS_SOCKET_MCAST_IPV4].fd < 0) {
		if (mdns_socket_open(iface, MDNS_SOCKET_MCAST_IPV4) < 0)
			return -1;
		opened_ipv4 = true;
	}

	/* Open IPv6 socket if requested and addresses available */
	if (ipv6 && iface->ipv6.count > 0 && iface->sockets[MDNS_SOCKET_MCAST_IPV6].fd < 0) {
		if (mdns_socket_open(iface, MDNS_SOCKET_MCAST_IPV6) < 0) {
			if (opened_ipv4)
				mdns_socket_close(&iface->sockets[MDNS_SOCKET_MCAST_IPV4]);
			return -1;
		}
	}

	iface->enabled = true;
	return 0;
}

/**
 * mdns_interface_disable() - disable mDNS on interface
 * @iface: interface to disable
 *
 * Closes all sockets, marks interface disabled.
 */
void mdns_interface_disable(struct mdns_interface *iface)
{
	if (!iface)
		return;

	for (int i = 0; i < MDNS_SOCKET_MAX; i++)
		mdns_socket_close(&iface->sockets[i]);

	iface->enabled = false;
}

/**
 * mdns_interface_update_addrs() - refresh interface address list
 * @iface: interface to update
 *
 * Queries current addresses via getifaddrs(), updates interface state.
 */
void mdns_interface_update_addrs(struct mdns_interface *iface)
{
	struct ifaddrs *ifap, *ifa;
	int ipv4_count = 0, ipv6_count = 0;
	struct in_addr *ipv4_addrs = NULL, *ipv4_netmasks = NULL;
	struct in6_addr *ipv6_addrs = NULL;
	uint8_t *ipv6_prefixlens = NULL;

	if (!iface)
		return;

	if (getifaddrs(&ifap) < 0)
		return;

	/* Count addresses */
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, iface->name) != 0)
			continue;

		/* ifa_addr can be NULL for interfaces without addresses */
		if (!ifa->ifa_addr)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET)
			ipv4_count++;
		else if (ifa->ifa_addr->sa_family == AF_INET6)
			ipv6_count++;
	}

	/* Allocate arrays */
	if (ipv4_count > 0) {
		ipv4_addrs = calloc(ipv4_count, sizeof(struct in_addr));
		ipv4_netmasks = calloc(ipv4_count, sizeof(struct in_addr));
		if (!ipv4_addrs || !ipv4_netmasks) {
			free(ipv4_addrs);
			free(ipv4_netmasks);
			goto out;
		}
	}

	if (ipv6_count > 0) {
		ipv6_addrs = calloc(ipv6_count, sizeof(struct in6_addr));
		ipv6_prefixlens = calloc(ipv6_count, sizeof(uint8_t));
		if (!ipv6_addrs || !ipv6_prefixlens) {
			free(ipv4_addrs);
			free(ipv4_netmasks);
			free(ipv6_addrs);
			free(ipv6_prefixlens);
			goto out;
		}
	}

	/* Copy addresses and netmasks */
	ipv4_count = 0;
	ipv6_count = 0;
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, iface->name) != 0)
			continue;

		/* ifa_addr can be NULL for interfaces without addresses */
		if (!ifa->ifa_addr)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
			struct sockaddr_in *netmask = (struct sockaddr_in *)ifa->ifa_netmask;
			ipv4_addrs[ipv4_count] = sa->sin_addr;
			if (netmask)
				ipv4_netmasks[ipv4_count] = netmask->sin_addr;
			else
				ipv4_netmasks[ipv4_count].s_addr = htonl(0xFFFFFF00);  /* Default /24 */
			ipv4_count++;
		} else if (ifa->ifa_addr->sa_family == AF_INET6) {
			struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			ipv6_addrs[ipv6_count] = sa6->sin6_addr;
			/* Calculate prefix length from netmask */
			if (ifa->ifa_netmask) {
				struct sockaddr_in6 *netmask6 = (struct sockaddr_in6 *)ifa->ifa_netmask;
				uint8_t prefixlen = 0;
				for (int i = 0; i < 16; i++) {
					uint8_t byte = netmask6->sin6_addr.s6_addr[i];
					while (byte) {
						prefixlen += (byte & 1);
						byte >>= 1;
					}
				}
				ipv6_prefixlens[ipv6_count] = prefixlen;
			} else {
				ipv6_prefixlens[ipv6_count] = 64;  /* Default /64 */
			}
			ipv6_count++;
		}
	}

	/* Update interface */
	free(iface->ipv4.addrs);
	free(iface->ipv4.netmasks);
	free(iface->ipv6.addrs);
	free(iface->ipv6.prefixlens);
	iface->ipv4.addrs = ipv4_addrs;
	iface->ipv4.netmasks = ipv4_netmasks;
	iface->ipv4.count = ipv4_count;
	iface->ipv6.addrs = ipv6_addrs;
	iface->ipv6.prefixlens = ipv6_prefixlens;
	iface->ipv6.count = ipv6_count;

out:
	freeifaddrs(ifap);
}
