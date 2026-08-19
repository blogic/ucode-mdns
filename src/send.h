/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 */

#ifndef MDNS_SEND_H
#define MDNS_SEND_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

/**
 * mdns_send_datagram() - send a datagram out of a given interface
 * @fd: socket
 * @ifindex: index of the egress interface
 * @data: datagram bytes
 * @length: datagram length
 * @dest: destination address
 * @dest_len: destination address length
 *
 * Packet info pins the egress interface for unicast as well as multicast
 * destinations, so a reply leaves through the link its query came in on.
 *
 * Return: bytes sent, or -1 with errno set
 */
static inline ssize_t mdns_send_datagram(int fd, unsigned int ifindex,
					 const void *data, size_t length,
					 struct sockaddr *dest, socklen_t dest_len)
{
	union {
		struct cmsghdr align;
		char bytes[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	} control = {};
	struct iovec iov = { .iov_base = (void *)data, .iov_len = length };
	struct msghdr msg = {
		.msg_name = dest,
		.msg_namelen = dest_len,
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = &control
	};
	struct cmsghdr *cm = (void *)&control;

	if (dest->sa_family == AF_INET) {
		msg.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
		cm->cmsg_level = IPPROTO_IP;
		cm->cmsg_type = IP_PKTINFO;
		cm->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
		((struct in_pktinfo *)CMSG_DATA(cm))->ipi_ifindex = ifindex;
	} else {
		msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
		cm->cmsg_level = IPPROTO_IPV6;
		cm->cmsg_type = IPV6_PKTINFO;
		cm->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
		((struct in6_pktinfo *)CMSG_DATA(cm))->ipi6_ifindex = ifindex;
	}

	return sendmsg(fd, &msg, 0);
}

#endif
