/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "mdns.h"
#include "send.h"

#define QUEUE_TIMER_INTERVAL	100	/* Process queue every 100ms */
#define QUEUE_MAX_BYTES		262144	/* Bytes held across all queued packets */
#define QUEUE_DEADLINE_MS	10000	/* Age at which a queued packet is stale */

struct queued_packet {
	struct list_head list;
	struct mdns_socket *sock;
	uint8_t *data;
	size_t len;
	struct sockaddr_storage dest;
	socklen_t dest_len;
	int64_t deadline;
};

static struct {
	struct list_head queue;
	struct uloop_timeout timer;
	size_t bytes;
	unsigned int dropped;
	unsigned int expired;
} pkt_queue;

static void queued_packet_free(struct queued_packet *pkt)
{
	list_del(&pkt->list);
	pkt->sock->queued--;
	pkt_queue.bytes -= pkt->len;
	free(pkt->data);
	free(pkt);
}

/**
 * packet_queue_process() - send queued packets the kernel now accepts
 * @t: uloop timeout (unused)
 *
 * Uloop timer callback. A socket whose send meets backpressure is stalled
 * for the rest of the pass, so its later packets wait behind the one that
 * failed. Reschedules itself while packets remain.
 */
static void packet_queue_process(struct uloop_timeout *t)
{
	struct queued_packet *pkt, *tmp;
	int64_t now = mdns_monotonic_ms();

	list_for_each_entry_safe(pkt, tmp, &pkt_queue.queue, list) {
		ssize_t sent;

		if (now >= pkt->deadline) {
			pkt_queue.expired++;
			queued_packet_free(pkt);
			continue;
		}

		if (pkt->sock->stalled)
			continue;

		if (pkt->sock->fd >= 0) {
			sent = mdns_send_datagram(pkt->sock->fd, pkt->sock->iface->ifindex,
						  pkt->data, pkt->len,
						  (struct sockaddr *)&pkt->dest, pkt->dest_len);

			if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS)) {
				pkt->sock->stalled = true;
				continue;
			}

			if (sent != (ssize_t)pkt->len)
				mdns_info("[queue] Queued packet send on %s failed: %s\n",
					  pkt->sock->iface->name, strerror(errno));
		}

		queued_packet_free(pkt);
	}

	list_for_each_entry(pkt, &pkt_queue.queue, list)
		pkt->sock->stalled = false;

	if (pkt_queue.dropped) {
		mdns_info("[queue] Dropped %u packet(s) over the %u byte queue limit\n",
			  pkt_queue.dropped, QUEUE_MAX_BYTES);
		pkt_queue.dropped = 0;
	}

	if (pkt_queue.expired) {
		mdns_info("[queue] Dropped %u packet(s) queued for more than %u ms\n",
			  pkt_queue.expired, QUEUE_DEADLINE_MS);
		pkt_queue.expired = 0;
	}

	if (!list_empty(&pkt_queue.queue))
		uloop_timeout_set(&pkt_queue.timer, QUEUE_TIMER_INTERVAL);
}

void packet_queue_init(void)
{
	INIT_LIST_HEAD(&pkt_queue.queue);
	pkt_queue.timer.cb = packet_queue_process;
}

void packet_queue_purge(struct mdns_interface *iface)
{
	struct queued_packet *pkt, *tmp;

	list_for_each_entry_safe(pkt, tmp, &pkt_queue.queue, list) {
		if (pkt->sock->iface == iface)
			queued_packet_free(pkt);
	}
}

void packet_queue_flush(void)
{
	struct queued_packet *pkt, *tmp;

	list_for_each_entry_safe(pkt, tmp, &pkt_queue.queue, list) {
		if (pkt->sock->fd >= 0)
			mdns_send_datagram(pkt->sock->fd, pkt->sock->iface->ifindex,
				pkt->data, pkt->len, (struct sockaddr *)&pkt->dest, pkt->dest_len);

		queued_packet_free(pkt);
	}
}

void packet_queue_cleanup(void)
{
	struct queued_packet *pkt, *tmp;

	uloop_timeout_cancel(&pkt_queue.timer);

	list_for_each_entry_safe(pkt, tmp, &pkt_queue.queue, list)
		queued_packet_free(pkt);
}

int packet_queue_add(struct mdns_socket *sock, const uint8_t *data, size_t len,
		     struct sockaddr *dest, socklen_t dest_len)
{
	struct queued_packet *pkt;

	if (len > MAX_PACKET_SIZE || dest_len > sizeof(struct sockaddr_storage))
		return -1;

	if (pkt_queue.bytes + len > QUEUE_MAX_BYTES) {
		pkt_queue.dropped++;
		return -1;
	}

	pkt = calloc(1, sizeof(*pkt));
	if (!pkt)
		return -1;

	pkt->data = malloc(len);
	if (!pkt->data) {
		free(pkt);
		return -1;
	}

	memcpy(pkt->data, data, len);
	pkt->len = len;
	pkt->sock = sock;
	memcpy(&pkt->dest, dest, dest_len);
	pkt->dest_len = dest_len;
	pkt->deadline = mdns_monotonic_ms() + QUEUE_DEADLINE_MS;

	list_add_tail(&pkt->list, &pkt_queue.queue);
	pkt_queue.bytes += len;
	sock->queued++;

	if (!pkt_queue.timer.pending)
		uloop_timeout_set(&pkt_queue.timer, QUEUE_TIMER_INTERVAL);

	if (ctx.debug)
		mdns_debug("[queue] Queued %zu byte packet on %s\n", len, sock->iface->name);

	return 0;
}

bool packet_queue_idle(struct mdns_socket **socks, int count)
{
	for (int i = 0; i < count; i++) {
		if (socks[i]->queued)
			return false;
	}

	return true;
}
