/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 */

#define _GNU_SOURCE
#undef NDEBUG
#define sendmsg test_sendmsg
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include "mdns.h"

static int64_t test_now;
static int blocked_fd = -1;
static uint8_t sent[16];
static int sent_count;

struct mdns_ctx ctx;
int64_t mdns_monotonic_ms(void) { return test_now; }
void mdns_info(const char *format, ...) {}
void mdns_debug(const char *format, ...) {}
void mdns_set_error(const char *format, ...) {}

ssize_t test_sendmsg(int fd, const struct msghdr *message, int flags)
{
	if (fd == blocked_fd && message->msg_iov[0].iov_len > 1000) {
		errno = EAGAIN;
		return -1;
	}

	sent[sent_count++] = ((uint8_t *)message->msg_iov[0].iov_base)[0];
	return message->msg_iov[0].iov_len;
}

#include "../src/queue.c"

static void queue(struct mdns_socket *sock, uint8_t tag, size_t len)
{
	struct sockaddr_in dest = { .sin_family = AF_INET };
	uint8_t data[MAX_PACKET_SIZE] = { tag };

	assert(packet_queue_add(sock, data, len, (void *)&dest, sizeof(dest)) == 0);
}

int main(void)
{
	struct mdns_interface iface = { .ifindex = 1, .name = "lan" };
	struct mdns_socket v4 = { .iface = &iface, .fd = 4 };
	struct mdns_socket v6 = { .iface = &iface, .fd = 6 };
	struct mdns_socket *both[] = { &v4, &v6 };
	struct sockaddr_in dest = { .sin_family = AF_INET };
	uint8_t data[MAX_PACKET_SIZE + 1] = {};

	packet_queue_init();
	assert(packet_queue_idle(both, 2));

	queue(&v4, 1, 2000);
	queue(&v4, 2, 100);
	queue(&v6, 3, 100);
	assert(v4.queued == 2 && v6.queued == 1 && pkt_queue.bytes == 2200);
	assert(!packet_queue_idle(both, 2));
	assert(packet_queue_idle(&both[1], 0));

	blocked_fd = 4;
	packet_queue_process(NULL);
	assert(sent_count == 1 && sent[0] == 3);
	assert(v4.queued == 2 && v6.queued == 0 && !v4.stalled);

	blocked_fd = -1;
	packet_queue_process(NULL);
	assert(sent_count == 3 && sent[1] == 1 && sent[2] == 2);
	assert(v4.queued == 0 && pkt_queue.bytes == 0);

	assert(packet_queue_add(&v4, data, MAX_PACKET_SIZE + 1, (void *)&dest, sizeof(dest)) == -1);
	pkt_queue.bytes = QUEUE_MAX_BYTES;
	assert(packet_queue_add(&v4, data, 100, (void *)&dest, sizeof(dest)) == -1);
	pkt_queue.bytes = 0;

	blocked_fd = 4;
	queue(&v4, 4, 2000);
	test_now += QUEUE_DEADLINE_MS;
	packet_queue_process(NULL);
	assert(v4.queued == 0 && pkt_queue.bytes == 0 && sent_count == 3);

	packet_queue_cleanup();
	return 0;
}
