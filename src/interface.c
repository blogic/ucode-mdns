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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>

#include "mdns.h"

static struct mdns_interface *interface_find_index(int index)
{
	struct mdns_interface *iface;

	avl_for_each_element(&ctx.interfaces, iface, node) {
		if (iface->ifindex == index)
			return iface;
	}
	return NULL;
}

static void link_mtu_update(struct mdns_interface *iface, struct nlmsghdr *nh)
{
	struct ifinfomsg *ifi = NLMSG_DATA(nh);
	int attr_len = IFLA_PAYLOAD(nh);

	for (struct rtattr *rta = IFLA_RTA(ifi); RTA_OK(rta, attr_len); rta = RTA_NEXT(rta, attr_len)) {
		if (rta->rta_type == IFLA_MTU && RTA_PAYLOAD(rta) >= sizeof(uint32_t))
			iface->mtu = *(uint32_t *)RTA_DATA(rta);
	}
}

static void interface_mtu_load(struct mdns_interface *iface)
{
	struct ifreq request = {};

	snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", iface->name);

	for (int i = 0; i < MDNS_SOCKET_MAX; i++) {
		if (iface->sockets[i].fd < 0)
			continue;

		if (!ioctl(iface->sockets[i].fd, SIOCGIFMTU, &request) && request.ifr_mtu > 0)
			iface->mtu = request.ifr_mtu;
		return;
	}
}

static bool onlink6_parse(struct nlmsghdr *nh, int *oif, struct mdns_onlink6 *route)
{
	struct rtmsg *rtm = NLMSG_DATA(nh);
	int attr_len = RTM_PAYLOAD(nh);

	if (nh->nlmsg_len < NLMSG_LENGTH(sizeof(*rtm)) || rtm->rtm_family != AF_INET6 ||
	    rtm->rtm_type != RTN_UNICAST || rtm->rtm_dst_len > 128)
		return false;

	memset(route, 0, sizeof(*route));
	route->len = rtm->rtm_dst_len;
	route->table = rtm->rtm_table;
	*oif = 0;

	for (struct rtattr *rta = RTM_RTA(rtm); RTA_OK(rta, attr_len); rta = RTA_NEXT(rta, attr_len)) {
		switch (rta->rta_type) {
		case RTA_GATEWAY:
		case RTA_MULTIPATH:
		case RTA_NH_ID:
			return false;
		case RTA_DST:
			if (RTA_PAYLOAD(rta) < sizeof(route->prefix))
				return false;
			memcpy(&route->prefix, RTA_DATA(rta), sizeof(route->prefix));
			break;
		case RTA_OIF:
			if (RTA_PAYLOAD(rta) >= sizeof(int))
				*oif = *(int *)RTA_DATA(rta);
			break;
		case RTA_TABLE:
			if (RTA_PAYLOAD(rta) >= sizeof(uint32_t))
				route->table = *(uint32_t *)RTA_DATA(rta);
			break;
		case RTA_PRIORITY:
			if (RTA_PAYLOAD(rta) >= sizeof(uint32_t))
				route->priority = *(uint32_t *)RTA_DATA(rta);
			break;
		}
	}

	return *oif > 0;
}

static int onlink6_find(struct mdns_interface *iface, const struct mdns_onlink6 *route)
{
	for (int i = 0; i < iface->onlink6.count; i++) {
		struct mdns_onlink6 *entry = &iface->onlink6.routes[i];

		if (entry->len == route->len && entry->table == route->table &&
		    entry->priority == route->priority &&
		    IN6_ARE_ADDR_EQUAL(&entry->prefix, &route->prefix))
			return i;
	}

	return -1;
}

static void onlink6_update(struct nlmsghdr *nh)
{
	struct mdns_onlink6 route, *routes;
	struct mdns_interface *iface;
	int oif, pos;

	if (!onlink6_parse(nh, &oif, &route))
		return;

	iface = interface_find_index(oif);
	if (!iface)
		return;

	pos = onlink6_find(iface, &route);

	if (nh->nlmsg_type == RTM_DELROUTE) {
		if (pos < 0)
			return;
		iface->onlink6.routes[pos] = iface->onlink6.routes[--iface->onlink6.count];
		return;
	}

	if (pos >= 0)
		return;

	routes = realloc(iface->onlink6.routes, (iface->onlink6.count + 1) * sizeof(*routes));
	if (!routes)
		return;

	routes[iface->onlink6.count++] = route;
	iface->onlink6.routes = routes;
}

static void onlink6_load(struct mdns_interface *iface)
{
	struct {
		struct nlmsghdr nh;
		struct rtmsg rtm;
	} req = {
		.nh = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
			.nlmsg_type = RTM_GETROUTE,
			.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
		},
		.rtm = { .rtm_family = AF_INET6 },
	};
	struct timeval timeout = { .tv_sec = 1 };
	char buf[16384];
	bool done = false;
	int fd;

	iface->onlink6.count = 0;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return;

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

	if (send(fd, &req, req.nh.nlmsg_len, 0) != (ssize_t)req.nh.nlmsg_len)
		done = true;

	while (!done) {
		ssize_t len = recv(fd, buf, sizeof(buf), 0);

		if (len <= 0)
			break;

		for (struct nlmsghdr *nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len);
		     nh = NLMSG_NEXT(nh, len)) {
			if (nh->nlmsg_type == NLMSG_DONE || nh->nlmsg_type == NLMSG_ERROR) {
				done = true;
				break;
			}

			if (nh->nlmsg_type == RTM_NEWROUTE)
				onlink6_update(nh);
		}
	}

	close(fd);
}

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
				link_mtu_update(iface, nh);

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
				} else {
					mdns_interface_disable(iface);
					mdns_callback_interface_change(iface, MDNS_IFACE_DOWN);
				}
			}
			break;

		case RTM_DELLINK:
			ifi = NLMSG_DATA(nh);
			iface = interface_find_index(ifi->ifi_index);
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
				bool changed = mdns_interface_update_addrs(iface);
				bool enabled = iface->enabled;

				mdns_interface_enable(iface, iface->want_ipv4,
						      iface->want_ipv6);
				if (changed || enabled != iface->enabled)
					mdns_callback_interface_change(iface, MDNS_IFACE_ADDR_ADD);
			}
			break;

		case RTM_DELADDR:
			ifa = NLMSG_DATA(nh);
			if (!if_indextoname(ifa->ifa_index, ifname))
				break;
			iface = mdns_interface_get(ifname);
			if (iface) {
				if (mdns_interface_update_addrs(iface))
					mdns_callback_interface_change(iface, MDNS_IFACE_ADDR_DEL);
			}
			break;

		case RTM_NEWROUTE:
		case RTM_DELROUTE:
			onlink6_update(nh);
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
	sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE;

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
	free(iface->onlink6.routes);
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
	if (!iface->ipv4.count && !iface->ipv6.count) {
		mdns_interface_disable(iface);
		return 0;
	}

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

	if (!iface->enabled && ipv6)
		onlink6_load(iface);

	if (!iface->mtu)
		interface_mtu_load(iface);

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
 *
 * Return: true if the address list changed
 */
bool mdns_interface_update_addrs(struct mdns_interface *iface)
{
	struct ifaddrs *ifap, *ifa;
	int ipv4_count = 0, ipv6_count = 0;
	struct in_addr *ipv4_addrs = NULL, *ipv4_netmasks = NULL;
	struct in6_addr *ipv6_addrs = NULL;
	uint8_t *ipv6_prefixlens = NULL;
	bool changed = false;

	if (!iface)
		return false;

	if (getifaddrs(&ifap) < 0)
		return false;

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
	changed = iface->ipv4.count != ipv4_count || iface->ipv6.count != ipv6_count;
	if (!changed && ipv4_count)
		changed = memcmp(iface->ipv4.addrs, ipv4_addrs, ipv4_count * sizeof(*ipv4_addrs)) ||
			memcmp(iface->ipv4.netmasks, ipv4_netmasks, ipv4_count * sizeof(*ipv4_netmasks));
	if (!changed && ipv6_count)
		changed = memcmp(iface->ipv6.addrs, ipv6_addrs, ipv6_count * sizeof(*ipv6_addrs)) ||
			memcmp(iface->ipv6.prefixlens, ipv6_prefixlens, ipv6_count * sizeof(*ipv6_prefixlens));
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
	return changed;
}

/**
 * mdns_interface_onlink6() - check whether an IPv6 address is on link
 * @iface: interface the address was seen on
 * @addr: IPv6 address
 *
 * RFC 6762 Section 11: a unicast source is local if it falls in an on-link
 * prefix of the interface. The prefixes are the routes of the kernel that
 * leave through @iface without a gateway, loaded when the interface is
 * enabled and kept current from route notifications.
 *
 * Return: true if the address is on link on @iface
 */
bool mdns_interface_onlink6(struct mdns_interface *iface, const struct in6_addr *addr)
{
	for (int i = 0; i < iface->onlink6.count; i++) {
		struct mdns_onlink6 *route = &iface->onlink6.routes[i];

		if (mdns_ipv6_prefix_match(addr, &route->prefix, route->len))
			return true;
	}

	return false;
}
