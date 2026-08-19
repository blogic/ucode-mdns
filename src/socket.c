/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 */

/* struct in6_pktinfo requires _GNU_SOURCE */
#define _GNU_SOURCE

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "mdns.h"

/**
 * socket_recv_cb() - socket receive callback invoked by uloop
 * @ufd: uloop file descriptor
 * @events: event flags
 *
 * Called when data available on socket. Validates source port (RFC 6762
 * Section 6) and source address (RFC 6762 Section 11), parses packet,
 * and invokes ucode callback.
 */
static void socket_recv_cb(struct uloop_fd *ufd, unsigned int events)
{
	struct mdns_socket *sock = container_of(ufd, struct mdns_socket, ufd);
	uint8_t buffer[MAX_PACKET_SIZE];
	/* CMSG_FIRSTHDR() reads a size_t out of this, so it has to be aligned
	 * for one; a uint8_t array has declared alignment 1 */
	union {
		struct cmsghdr align;
		uint8_t buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	} cbuf;
	struct sockaddr_storage from;
	socklen_t from_len = sizeof(from);
	ssize_t len;
	struct iovec iov = {
		.iov_base = buffer,
		.iov_len = sizeof(buffer)
	};
	struct msghdr msg = {
		.msg_name = &from,
		.msg_namelen = from_len,
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf.buf,
		.msg_controllen = sizeof(cbuf.buf)
	};

	memset(&from, 0, sizeof(from));

	len = recvmsg(sock->fd, &msg, 0);
	if (len < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			mdns_set_error("recvmsg failed: %s", strerror(errno));
		return;
	}

	if (len == 0)
		return;

	/* A datagram larger than the buffer was silently cut short, so what is
	 * left is not the packet the sender built */
	if (msg.msg_flags & MSG_TRUNC) {
		mdns_debug("Dropped datagram truncated at %d bytes\n", MAX_PACKET_SIZE);
		return;
	}

	/* RFC 6762 Section 6.7: Detect legacy unicast queries (non-5353 source port)
	 * Legacy queries from non-5353 ports require special handling:
	 * - Send unicast response (not multicast)
	 * - Match query ID in response
	 * - Must NOT set cache-flush bit
	 * - TTL should not exceed 10 seconds */
	uint16_t src_port = 0;
	if (from.ss_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&from;
		src_port = ntohs(sin->sin_port);
	} else if (from.ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&from;
		src_port = ntohs(sin6->sin6_port);
	}

	/* Destination address from packet info, needed for the RFC 6762
	 * Section 11 locality test and the multicast/unicast distinction */
	bool have_dest = false;
	bool mcast_dest = false;

	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
			struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cmsg);

			mcast_dest = IN_MULTICAST(ntohl(pi->ipi_addr.s_addr));
			have_dest = true;
		} else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
			struct in6_pktinfo *pi6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);

			mcast_dest = IN6_IS_ADDR_MULTICAST(&pi6->ipi6_addr);
			have_dest = true;
		}
	}

	/* RFC 6762 Section 11: the source address decides locality. The
	 * destination says nothing about it, and anyone on the link may put an
	 * arbitrary source in a packet addressed to the multicast group */
	bool valid_source = false;

	if (from.ss_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&from;
		uint32_t addr = ntohl(sin->sin_addr.s_addr);

		/* Check if link-local (169.254.0.0/16) */
		if ((addr & 0xFFFF0000) == 0xA9FE0000) {
			valid_source = true;
		} else {
			/* Check if same subnet as any interface address */
			for (int i = 0; i < sock->iface->ipv4.count; i++) {
				uint32_t iface_addr = ntohl(sock->iface->ipv4.addrs[i].s_addr);
				uint32_t netmask = ntohl(sock->iface->ipv4.netmasks[i].s_addr);
				if ((addr & netmask) == (iface_addr & netmask)) {
					valid_source = true;
					break;
				}
			}
		}
	} else if (from.ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&from;

		/* Check if link-local (fe80::/10) */
		if (sin6->sin6_addr.s6_addr[0] == 0xfe &&
		    (sin6->sin6_addr.s6_addr[1] & 0xc0) == 0x80) {
			valid_source = true;
		} else {
			/* Check if same subnet as any interface address */
			for (int i = 0; i < sock->iface->ipv6.count; i++) {
				/* Use actual prefix length from interface */
				uint8_t prefixlen = sock->iface->ipv6.prefixlens[i];
				uint8_t prefix_bytes = prefixlen / 8;
				uint8_t prefix_bits = prefixlen % 8;

				/* Compare full bytes */
				if (prefix_bytes > 0 &&
				    memcmp(&sin6->sin6_addr, &sock->iface->ipv6.addrs[i], prefix_bytes) != 0)
					continue;

				/* Compare remaining bits if any */
				if (prefix_bits > 0) {
					uint8_t mask = 0xFF << (8 - prefix_bits);
					if ((sin6->sin6_addr.s6_addr[prefix_bytes] & mask) !=
					    (sock->iface->ipv6.addrs[i].s6_addr[prefix_bytes] & mask))
						continue;
				}

				valid_source = true;
				break;
			}
		}
	}

	if (!valid_source) {
		if (ctx.debug) {
			char addr_str[INET6_ADDRSTRLEN];
			if (from.ss_family == AF_INET) {
				inet_ntop(AF_INET, &((struct sockaddr_in *)&from)->sin_addr,
					  addr_str, sizeof(addr_str));
			} else {
				inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&from)->sin6_addr,
					  addr_str, sizeof(addr_str));
			}
			mdns_debug("Dropped packet from non-local address %s\n", addr_str);
		}
		return;
	}

	/* Debug: log packet reception */
	if (ctx.debug) {
		char addr_str[INET6_ADDRSTRLEN];

		if (from.ss_family == AF_INET) {
			inet_ntop(AF_INET, &((struct sockaddr_in *)&from)->sin_addr,
				  addr_str, sizeof(addr_str));
		} else if (from.ss_family == AF_INET6) {
			inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&from)->sin6_addr,
				  addr_str, sizeof(addr_str));
		}

		mdns_debug("RX %zd bytes from %s:%d on %s (%s)\n",
			   len, addr_str, src_port, sock->iface->name,
			   sock->type == MDNS_SOCKET_MCAST_IPV4 || sock->type == MDNS_SOCKET_MCAST_IPV6 ? "multicast" : "unicast");
	}

	/* Parse DNS packet */
	struct mdns_packet *pkt = mdns_packet_parse(buffer, len);
	if (!pkt) {
		mdns_debug("Failed to parse packet: %s\n", ctx.error);
		return;
	}

	/* RFC 6762 Section 6: MUST silently ignore responses from non-5353 source ports
	 * Legacy queries (from non-5353) are allowed per Section 6.7 */
	bool is_response = (pkt->header.flags & DNS_FLAG_RESPONSE) != 0;
	bool is_legacy = (src_port != MDNS_PORT);

	if (is_response && is_legacy) {
		mdns_debug("Dropped response from non-5353 port %d\n", src_port);
		mdns_packet_free(pkt);
		return;
	}

	/* Use the packet destination when available; the 5353-bound sockets
	 * also receive unicast packets, so socket type alone is unreliable */
	bool multicast = have_dest ? mcast_dest :
			 (sock->type == MDNS_SOCKET_MCAST_IPV4 ||
			  sock->type == MDNS_SOCKET_MCAST_IPV6);

	/* Invoke ucode callback */
	mdns_callback_packet(sock->iface, pkt, &from, multicast, is_legacy);

	mdns_packet_free(pkt);
}

/**
 * open_mcast_ipv4() - open and configure IPv4 multicast socket
 * @iface: interface to bind to
 *
 * Creates UDP socket, binds to mDNS port, joins multicast group,
 * sets socket options for multicast operation.
 *
 * Return: socket file descriptor, or -1 on error
 */
static int open_mcast_ipv4(struct mdns_interface *iface)
{
	struct sockaddr_in addr;
	struct ip_mreqn mreq;
	int fd, val;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP);
	if (fd < 0) {
		mdns_set_error("Failed to create IPv4 socket: %s", strerror(errno));
		return -1;
	}

	/* Allow address reuse */
	val = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
		mdns_set_error("SO_REUSEADDR failed: %s", strerror(errno));
		goto error;
	}

#ifdef SO_REUSEPORT
	val = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
#endif

	/* Bind to mDNS port */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(MDNS_PORT);
	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		mdns_set_error("bind failed: %s", strerror(errno));
		goto error;
	}

	/* Join multicast group on this interface */
	memset(&mreq, 0, sizeof(mreq));
	inet_pton(AF_INET, MDNS_MCAST_ADDR_IPV4, &mreq.imr_multiaddr);
	mreq.imr_address.s_addr = INADDR_ANY;
	mreq.imr_ifindex = iface->ifindex;

	if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
		mdns_set_error("IP_ADD_MEMBERSHIP failed: %s", strerror(errno));
		goto error;
	}

	/* A responder must not process its own packets: with loopback on we
	 * answer our own probes, defend our name against ourselves and cache
	 * our own announcements as if they came from the network */
	val = 0;
	setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &val, sizeof(val));

	/* Set outgoing interface by index; passing only an INADDR_ANY
	 * address would select the default route interface instead */
	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &mreq, sizeof(mreq)) < 0) {
		mdns_set_error("IP_MULTICAST_IF failed: %s", strerror(errno));
		goto error;
	}

	/* RFC 6762 Section 11: all responses, unicast ones included, carry 255 */
	val = 255;
	setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &val, sizeof(val));
	setsockopt(fd, IPPROTO_IP, IP_TTL, &val, sizeof(val));

	/* Enable packet info to get destination address */
	val = 1;
	setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &val, sizeof(val));

	return fd;

error:
	close(fd);
	return -1;
}

/**
 * open_mcast_ipv6() - open and configure IPv6 multicast socket
 * @iface: interface to bind to
 *
 * Creates UDP socket, binds to mDNS port, joins multicast group,
 * sets socket options for multicast operation.
 *
 * Return: socket file descriptor, or -1 on error
 */
static int open_mcast_ipv6(struct mdns_interface *iface)
{
	struct sockaddr_in6 addr;
	struct ipv6_mreq mreq;
	int fd, val;

	fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP);
	if (fd < 0) {
		mdns_set_error("Failed to create IPv6 socket: %s", strerror(errno));
		return -1;
	}

	/* Allow address reuse */
	val = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
		mdns_set_error("SO_REUSEADDR failed: %s", strerror(errno));
		goto error;
	}

#ifdef SO_REUSEPORT
	val = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
#endif

	/* IPv6 only */
	val = 1;
	setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));

	/* Bind to mDNS port */
	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(MDNS_PORT);
	addr.sin6_addr = in6addr_any;

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		mdns_set_error("IPv6 bind failed: %s", strerror(errno));
		goto error;
	}

	/* Join multicast group */
	memset(&mreq, 0, sizeof(mreq));
	inet_pton(AF_INET6, MDNS_MCAST_ADDR_IPV6, &mreq.ipv6mr_multiaddr);
	mreq.ipv6mr_interface = iface->ifindex;

	if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) < 0) {
		mdns_set_error("IPV6_JOIN_GROUP failed: %s", strerror(errno));
		goto error;
	}

	/* See the IPv4 path: our own multicast must not come back to us */
	val = 0;
	setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &val, sizeof(val));

	/* Set outgoing interface */
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &iface->ifindex, sizeof(iface->ifindex)) < 0) {
		mdns_set_error("IPV6_MULTICAST_IF failed: %s", strerror(errno));
		goto error;
	}

	/* RFC 6762 Section 11: all responses, unicast ones included, carry 255 */
	val = 255;
	setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val, sizeof(val));
	setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &val, sizeof(val));

	/* Enable packet info */
	val = 1;
	setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val, sizeof(val));

	return fd;

error:
	close(fd);
	return -1;
}

/**
 * mdns_socket_open() - open socket of specified type
 * @iface: interface to bind socket to
 * @type: socket type (multicast/unicast, IPv4/IPv6)
 *
 * Opens socket, configures for mDNS operation, registers with uloop.
 *
 * Return: 0 on success, -1 on error
 */
int mdns_socket_open(struct mdns_interface *iface, enum mdns_socket_type type)
{
	struct mdns_socket *sock = &iface->sockets[type];
	int fd;

	if (sock->fd >= 0)
		return 0;

	switch (type) {
	case MDNS_SOCKET_MCAST_IPV4:
		fd = open_mcast_ipv4(iface);
		break;
	case MDNS_SOCKET_MCAST_IPV6:
		fd = open_mcast_ipv6(iface);
		break;
	default:
		mdns_set_error("Invalid socket type");
		return -1;
	}

	if (fd < 0)
		return -1;

	sock->fd = fd;
	sock->type = type;
	sock->iface = iface;
	sock->ufd.fd = fd;
	sock->ufd.cb = socket_recv_cb;

	uloop_fd_add(&sock->ufd, ULOOP_READ);

	return 0;
}

/**
 * mdns_socket_close() - close socket and release resources
 * @sock: socket to close
 *
 * Removes from uloop, closes file descriptor, resets state.
 */
void mdns_socket_close(struct mdns_socket *sock)
{
	if (!sock || sock->fd < 0)
		return;

	uloop_fd_delete(&sock->ufd);
	close(sock->fd);
	sock->fd = -1;
}

/**
 * mdns_socket_send() - send packet through socket
 * @sock: socket to send through
 * @data: packet data
 * @len: packet length
 * @dest: destination address (NULL for multicast)
 * @dest_len: destination address length
 *
 * Sends packet, applying rate limiting. Automatically selects multicast
 * destination if dest is NULL.
 *
 * Return: 0 on success, -1 on error
 */
int mdns_socket_send(struct mdns_socket *sock, const uint8_t *data, size_t len,
		     struct sockaddr *dest, socklen_t dest_len)
{
	struct sockaddr_storage mcast_addr;
	ssize_t ret;

	if (!sock || sock->fd < 0) {
		mdns_set_error("Invalid socket");
		return -1;
	}

	/* Resolve the multicast destination up front so queued packets
	 * carry a complete destination as well */
	if (!dest) {
		memset(&mcast_addr, 0, sizeof(mcast_addr));

		if (sock->type == MDNS_SOCKET_MCAST_IPV4) {
			struct sockaddr_in *sin = (struct sockaddr_in *)&mcast_addr;
			sin->sin_family = AF_INET;
			sin->sin_port = htons(MDNS_PORT);
			inet_pton(AF_INET, MDNS_MCAST_ADDR_IPV4, &sin->sin_addr);
			dest_len = sizeof(*sin);
		} else if (sock->type == MDNS_SOCKET_MCAST_IPV6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&mcast_addr;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_port = htons(MDNS_PORT);
			inet_pton(AF_INET6, MDNS_MCAST_ADDR_IPV6, &sin6->sin6_addr);
			dest_len = sizeof(*sin6);
		} else {
			mdns_set_error("Cannot send without destination on unicast socket");
			return -1;
		}

		dest = (struct sockaddr *)&mcast_addr;
	}

	/* Try to queue packet if rate limited, otherwise send immediately */
	if (packet_queue_send(sock, data, len, dest, dest_len))
		return 0;

	ret = sendto(sock->fd, data, len, 0, dest, dest_len);

	if (ret < 0) {
		mdns_set_error("sendto failed: %s", strerror(errno));
		return -1;
	}

	if ((size_t)ret != len) {
		mdns_set_error("Partial send: %zd of %zu bytes", ret, len);
		return -1;
	}

	/* Debug: log packet transmission */
	if (ctx.debug) {
		char addr_str[INET6_ADDRSTRLEN] = "multicast";
		int port = MDNS_PORT;

		if (dest) {
			if (dest->sa_family == AF_INET) {
				struct sockaddr_in *sin = (struct sockaddr_in *)dest;
				inet_ntop(AF_INET, &sin->sin_addr, addr_str, sizeof(addr_str));
				port = ntohs(sin->sin_port);
			} else if (dest->sa_family == AF_INET6) {
				struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)dest;
				inet_ntop(AF_INET6, &sin6->sin6_addr, addr_str, sizeof(addr_str));
				port = ntohs(sin6->sin6_port);
			}
		}

		mdns_debug("TX %zu bytes to %s:%d on %s\n",
			   len, addr_str, port, sock->iface->name);
	}

	return 0;
}
