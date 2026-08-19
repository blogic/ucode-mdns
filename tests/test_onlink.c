/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 */

#define _GNU_SOURCE
#undef NDEBUG
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "mdns.h"

int mdns_socket_open(struct mdns_interface *iface, enum mdns_socket_type type) { return 0; }
void mdns_socket_close(struct mdns_socket *sock) {}
void mdns_callback_interface_change(struct mdns_interface *iface, enum mdns_interface_event event) {}
void packet_queue_purge(struct mdns_interface *iface) {}
#include "../src/interface.c"

static bool onlink(struct mdns_interface *iface, const char *text)
{
	struct in6_addr addr;

	assert(inet_pton(AF_INET6, text, &addr) == 1);
	return mdns_interface_onlink6(iface, &addr);
}

static void events_read(void)
{
	for (int i = 0; i < 32; i++)
		netlink_recv_cb(&ctx.netlink_fd, ULOOP_READ);
}

int main(void)
{
	struct mdns_interface *iface;

	avl_init(&ctx.interfaces, avl_strcmp, false, NULL);

	if (system("ip link add d0 type dummy && ip link set d0 up && "
		   "ip -6 addr add 2001:db8:1::1/64 dev d0 nodad && "
		   "ip -6 route add 2001:db8:7::/64 dev d0 && "
		   "ip -6 route add 2001:db8:9::/64 via 2001:db8:1::fe dev d0"))
		return 77;

	assert(mdns_interface_init() == 0);
	iface = mdns_interface_create("d0");
	assert(iface && mdns_interface_enable(iface, false, true) == 0);

	assert(onlink(iface, "2001:db8:7::5"));
	assert(onlink(iface, "2001:db8:1::5"));
	assert(!onlink(iface, "2001:db8:9::5"));
	assert(!onlink(iface, "2001:db8:5::5"));

	assert(!system("ip -6 route add 2001:db8:5::/64 dev d0 && "
		       "ip -6 route del 2001:db8:7::/64 dev d0"));
	events_read();

	assert(onlink(iface, "2001:db8:5::5"));
	assert(!onlink(iface, "2001:db8:7::5"));

	mdns_interface_cleanup();
	return 0;
}
