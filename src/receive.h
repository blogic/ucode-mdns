/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 */

#ifndef MDNS_RECEIVE_H
#define MDNS_RECEIVE_H

#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#define MDNS_GROUP_IPV4	0xe00000fbU

static const struct in6_addr mdns_group_ipv6 = {
	.s6_addr = { 0xff, 0x02, [15] = 0xfb }
};

/**
 * mdns_receive_info() - check the ingress interface of a received datagram
 * @msg: message header filled in by recvmsg()
 * @family: address family of the sender
 * @ifindex: index of the interface that owns the socket
 * @multicast: set to true if the destination is the mDNS group address
 *
 * Return: true if the packet info names @ifindex as the ingress interface,
 * false if it names another interface, is missing or truncated, or if the
 * destination is a multicast group other than the mDNS group
 */
static inline bool mdns_receive_info(struct msghdr *msg, int family,
				     unsigned int ifindex, bool *multicast)
{
	if (msg->msg_flags & MSG_CTRUNC)
		return false;

	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg;
	     cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (family == AF_INET && cmsg->cmsg_level == IPPROTO_IP &&
		    cmsg->cmsg_type == IP_PKTINFO &&
		    cmsg->cmsg_len >= CMSG_LEN(sizeof(struct in_pktinfo))) {
			struct in_pktinfo *pi = (void *)CMSG_DATA(cmsg);

			*multicast = pi->ipi_addr.s_addr == htonl(MDNS_GROUP_IPV4);
			if (IN_MULTICAST(ntohl(pi->ipi_addr.s_addr)) && !*multicast)
				return false;
			return pi->ipi_ifindex == ifindex;
		}
		if (family == AF_INET6 && cmsg->cmsg_level == IPPROTO_IPV6 &&
		    cmsg->cmsg_type == IPV6_PKTINFO &&
		    cmsg->cmsg_len >= CMSG_LEN(sizeof(struct in6_pktinfo))) {
			struct in6_pktinfo *pi = (void *)CMSG_DATA(cmsg);

			*multicast = IN6_ARE_ADDR_EQUAL(&pi->ipi6_addr, &mdns_group_ipv6);
			if (IN6_IS_ADDR_MULTICAST(&pi->ipi6_addr) && !*multicast)
				return false;
			return pi->ipi6_ifindex == ifindex;
		}
	}

	return false;
}
#endif
