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
#include "receive.h"
#include "send.h"

static bool source_is_local_ipv4(struct mdns_interface *iface, struct sockaddr_in *sin)
{
	uint32_t addr = ntohl(sin->sin_addr.s_addr);

	/* Link-local (169.254.0.0/16) */
	if ((addr & 0xFFFF0000) == 0xA9FE0000)
		return true;

	for (int i = 0; i < iface->ipv4.count; i++) {
		uint32_t iface_addr = ntohl(iface->ipv4.addrs[i].s_addr);
		uint32_t netmask = ntohl(iface->ipv4.netmasks[i].s_addr);

		if ((addr & netmask) == (iface_addr & netmask))
			return true;
	}

	return false;
}

static bool source_is_local_ipv6(struct mdns_interface *iface, struct sockaddr_in6 *sin6)
{
	/* Link-local (fe80::/10) */
	if (sin6->sin6_addr.s6_addr[0] == 0xfe &&
	    (sin6->sin6_addr.s6_addr[1] & 0xc0) == 0x80)
		return true;

	for (int i = 0; i < iface->ipv6.count; i++) {
		if (mdns_ipv6_prefix_match(&sin6->sin6_addr, &iface->ipv6.addrs[i],
					   iface->ipv6.prefixlens[i]))
			return true;
	}

	return mdns_interface_onlink6(iface, &sin6->sin6_addr);
}

static bool source_is_other_link(struct mdns_interface *ingress, struct sockaddr_storage *from)
{
	struct mdns_interface *iface;

	avl_for_each_element(&ctx.interfaces, iface, node) {
		if (iface == ingress)
			continue;

		for (int i = 0; from->ss_family == AF_INET && i < iface->ipv4.count; i++) {
			if (((struct sockaddr_in *)from)->sin_addr.s_addr == iface->ipv4.addrs[i].s_addr)
				return true;
		}

		for (int i = 0; from->ss_family == AF_INET6 && i < iface->ipv6.count; i++) {
			if (IN6_ARE_ADDR_EQUAL(&((struct sockaddr_in6 *)from)->sin6_addr, &iface->ipv6.addrs[i]))
				return true;
		}
	}

	return false;
}

static bool source_is_local(struct mdns_interface *iface, struct sockaddr_storage *from)
{
	if (from->ss_family == AF_INET)
		return source_is_local_ipv4(iface, (struct sockaddr_in *)from);
	if (from->ss_family == AF_INET6)
		return source_is_local_ipv6(iface, (struct sockaddr_in6 *)from);

	return false;
}

/**
 * socket_recv_cb() - socket receive callback invoked by uloop
 * @ufd: uloop file descriptor
 * @events: event flags
 *
 * Called when data available on socket. Validates source port (RFC 6762
 * Section 6) and source address (RFC 6762 Section 11), drops our own
 * packets that another of our interfaces on the same link sent (RFC 6762
 * Section 14), parses packet, and invokes ucode callback.
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
	bool mcast_dest = false;

	if (!mdns_receive_info(&msg, from.ss_family, sock->iface->ifindex, &mcast_dest)) {
		mdns_debug("Dropped packet without matching ingress interface on %s\n", sock->iface->name);
		return;
	}

	/* RFC 6762 Section 11: a packet addressed to the mDNS group is local
	 * whatever its source, peers on another logical subnet of this link
	 * included. A unicast packet is local only if its source is on link,
	 * and replies to a non-local source go to the group. */
	bool local_source = source_is_local(sock->iface, &from);

	if (source_is_other_link(sock->iface, &from)) {
		mdns_debug("Dropped own packet on %s\n", sock->iface->name);
		return;
	}

	if (!mcast_dest && !local_source) {
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
			   mcast_dest ? "multicast" : "unicast");
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

	/* Invoke ucode callback */
	mdns_callback_packet(sock->iface, pkt, &from, local_source, mcast_dest, is_legacy);

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
	if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &val, sizeof(val)) < 0) {
		mdns_set_error("IP_PKTINFO failed: %s", strerror(errno));
		goto error;
	}

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
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val, sizeof(val)) < 0) {
		mdns_set_error("IPV6_RECVPKTINFO failed: %s", strerror(errno));
		goto error;
	}

	return fd;

error:
	close(fd);
	return -1;
}

static bool port_free(int family)
{
	struct sockaddr_storage addr = {};
	socklen_t len;
	int val = 1;
	int fd = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	bool free_port;

	if (fd < 0)
		return true;

	if (family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&addr;

		sin->sin_family = AF_INET;
		sin->sin_port = htons(MDNS_PORT);
		len = sizeof(*sin);
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;

		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(MDNS_PORT);
		len = sizeof(*sin6);
	}

	free_port = bind(fd, (struct sockaddr *)&addr, len) == 0 || errno != EADDRINUSE;
	close(fd);

	return free_port;
}

/**
 * mdns_port_first_binder() - check that no other process holds port 5353
 *
 * RFC 6762 Section 15.1: with several processes on port 5353, only the first
 * to bind receives unicast replies reliably. Call this before any mDNS
 * socket is open.
 *
 * Return: true if port 5353 is free for IPv4 and IPv6
 */
bool mdns_port_first_binder(void)
{
	return port_free(AF_INET) && port_free(AF_INET6);
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

	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface->name, strlen(iface->name) + 1) < 0) {
		mdns_set_error("SO_BINDTODEVICE failed: %s", strerror(errno));
		close(fd);
		return -1;
	}

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

static int socket_queue(struct mdns_socket *sock, const uint8_t *data, size_t len,
			struct sockaddr *dest, socklen_t dest_len)
{
	if (packet_queue_add(sock, data, len, dest, dest_len) < 0) {
		mdns_set_error("Packet queue full on %s", sock->iface->name);
		return -1;
	}

	return 0;
}

/**
 * socket_send() - send packet through socket
 * @sock: socket to send through
 * @data: packet data
 * @len: packet length
 * @dest: destination address (NULL for multicast)
 * @dest_len: destination address length
 * @queue: queue the packet if it cannot go out now
 *
 * Automatically selects multicast destination if dest is NULL. With @queue,
 * the packet goes behind the packets already queued on the socket, and a
 * packet the kernel has no buffer space for is queued.
 *
 * Return: 0 when sent or queued, -1 on error
 */
static int socket_send(struct mdns_socket *sock, const uint8_t *data, size_t len,
		       struct sockaddr *dest, socklen_t dest_len, bool queue)
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

	/* Queue behind the packets already queued on this socket */
	if (queue && sock->queued)
		return socket_queue(sock, data, len, dest, dest_len);

	ret = mdns_send_datagram(sock->fd, sock->iface->ifindex, data, len, dest, dest_len);

	if (ret < 0 && queue && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS))
		return socket_queue(sock, data, len, dest, dest_len);

	if (ret < 0) {
		mdns_set_error("sendmsg failed: %s", strerror(errno));
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

/**
 * mdns_socket_send() - send or queue a packet on an mDNS socket
 * @sock: interface socket
 * @data: packet bytes
 * @len: packet length
 * @dest: optional destination, NULL for multicast
 * @dest_len: destination structure size
 *
 * Return: 0 when sent or queued, -1 on error
 */
int mdns_socket_send(struct mdns_socket *sock, const uint8_t *data, size_t len,
		     struct sockaddr *dest, socklen_t dest_len)
{
	return socket_send(sock, data, len, dest, dest_len, true);
}

/**
 * mdns_socket_send_now() - send a packet without adding it to the queue
 * @sock: interface socket
 * @data: packet bytes
 * @len: packet length
 * @dest: optional destination, NULL for multicast
 * @dest_len: destination structure size
 *
 * The caller checks with packet_queue_idle() that nothing is queued on the
 * socket, so the packet does not overtake queued ones.
 *
 * Return: 0 only after transmission, -1 if the send failed
 */
int mdns_socket_send_now(struct mdns_socket *sock, const uint8_t *data, size_t len,
			struct sockaddr *dest, socklen_t dest_len)
{
	return socket_send(sock, data, len, dest, dest_len, false);
}
