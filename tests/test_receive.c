/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 */

#define _GNU_SOURCE
#undef NDEBUG
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include "receive.h"
#define sendmsg test_sendmsg
static ssize_t test_sendmsg(int fd, const struct msghdr *message, int flags);
#include "send.h"
#undef sendmsg
static ssize_t test_sendmsg(int fd, const struct msghdr *message, int flags)
{
	bool multicast;
	assert(mdns_receive_info((struct msghdr *)message,
		((struct sockaddr *)message->msg_name)->sa_family, 7, &multicast));
	return message->msg_iov[0].iov_len;
}

int main(void)
{
	union { struct cmsghdr align; char data[CMSG_SPACE(sizeof(struct in6_pktinfo))]; } control;
	struct msghdr msg = { .msg_control = &control, .msg_controllen = sizeof(control) };
	struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
	bool multicast = false;

	memset(&control, 0, sizeof(control));
	cm->cmsg_level = IPPROTO_IP;
	cm->cmsg_type = IP_PKTINFO;
	cm->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
	struct in_pktinfo *v4 = (void *)CMSG_DATA(cm);
	v4->ipi_ifindex = 3;
	inet_pton(AF_INET, "224.0.0.251", &v4->ipi_addr);
	assert(mdns_receive_info(&msg, AF_INET, 3, &multicast) && multicast);
	assert(!mdns_receive_info(&msg, AF_INET, 4, &multicast));
	inet_pton(AF_INET, "239.1.2.3", &v4->ipi_addr);
	assert(!mdns_receive_info(&msg, AF_INET, 3, &multicast));
	inet_pton(AF_INET, "192.0.2.1", &v4->ipi_addr);
	assert(mdns_receive_info(&msg, AF_INET, 3, &multicast) && !multicast);
	assert(!mdns_receive_info(&msg, AF_INET6, 3, &multicast));
	cm->cmsg_len = CMSG_LEN(0);
	assert(!mdns_receive_info(&msg, AF_INET, 3, &multicast));

	cm->cmsg_level = IPPROTO_IPV6;
	cm->cmsg_type = IPV6_PKTINFO;
	cm->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	struct in6_pktinfo *v6 = (void *)CMSG_DATA(cm);
	v6->ipi6_ifindex = 3;
	inet_pton(AF_INET6, "ff02::fb", &v6->ipi6_addr);
	assert(mdns_receive_info(&msg, AF_INET6, 3, &multicast) && multicast);
	assert(!mdns_receive_info(&msg, AF_INET6, 4, &multicast));
	inet_pton(AF_INET6, "ff02::1", &v6->ipi6_addr);
	assert(!mdns_receive_info(&msg, AF_INET6, 3, &multicast));
	inet_pton(AF_INET6, "fe80::1", &v6->ipi6_addr);
	assert(mdns_receive_info(&msg, AF_INET6, 3, &multicast) && !multicast);
	msg.msg_flags = MSG_CTRUNC;
	assert(!mdns_receive_info(&msg, AF_INET6, 3, &multicast));
	msg.msg_flags = 0;
	msg.msg_controllen = 0;
	assert(!mdns_receive_info(&msg, AF_INET6, 3, &multicast));
	struct sockaddr_in to4 = { .sin_family = AF_INET };
	struct sockaddr_in6 to6 = { .sin6_family = AF_INET6 };
	assert(mdns_send_datagram(-1, 7, "test", 4, (void *)&to4, sizeof(to4)) == 4);
	assert(mdns_send_datagram(-1, 7, "test", 4, (void *)&to6, sizeof(to6)) == 4);
	return 0;
}
