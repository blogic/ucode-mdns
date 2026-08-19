/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "mdns.h"

/* RFC 6762 Section 6: Rate limiting parameters */
#define RATE_LIMITER_CAPACITY	5000	/* Burst capacity (bytes) */
#define RATE_LIMITER_RATE	1000	/* Refill rate (bytes/second) */
#define QUEUE_TIMER_INTERVAL	100	/* Process queue every 100ms */
#define QUEUE_MAX_BYTES		262144	/* Bytes held across all queued packets */

struct queued_packet {
	struct list_head list;
	struct mdns_socket *sock;
	uint8_t *data;
	size_t len;
	struct sockaddr_storage dest;
	socklen_t dest_len;
};

struct rate_limiter {
	struct avl_node node;
	int ifindex;
	int tokens;
	int64_t last_update;
};

static struct {
	struct list_head queue;
	struct uloop_timeout timer;
	struct avl_tree limiters;
	size_t bytes;
	unsigned int dropped;
} pkt_queue;

static void packet_queue_process(struct uloop_timeout *t);

/**
 * rate_limiter_cmp() - AVL tree comparison function for rate limiters
 * @k1: first interface index (as void pointer)
 * @k2: second interface index (as void pointer)
 * @ptr: unused context pointer
 *
 * Return: negative if k1 < k2, 0 if equal, positive if k1 > k2
 */
static int rate_limiter_cmp(const void *k1, const void *k2, void *ptr)
{
	int ifindex1 = (int)(uintptr_t)k1;
	int ifindex2 = (int)(uintptr_t)k2;
	return ifindex1 - ifindex2;
}

/**
 * rate_limiter_get() - get or create rate limiter for interface
 * @iface: interface to get rate limiter for
 *
 * Looks up existing rate limiter by interface index, creates new one if needed.
 *
 * Return: pointer to rate limiter, or NULL on allocation failure
 */
static struct rate_limiter *rate_limiter_get(struct mdns_interface *iface)
{
	struct rate_limiter *limiter;
	void *key = (void *)(uintptr_t)iface->ifindex;

	limiter = avl_find_element(&pkt_queue.limiters, key, limiter, node);
	if (limiter)
		return limiter;

	limiter = calloc(1, sizeof(*limiter));
	if (!limiter)
		return NULL;

	limiter->ifindex = iface->ifindex;
	limiter->tokens = RATE_LIMITER_CAPACITY;
	limiter->last_update = mdns_monotonic_ms();
	limiter->node.key = key;

	avl_insert(&pkt_queue.limiters, &limiter->node);

	return limiter;
}

/**
 * rate_limiter_check() - check if packet send is allowed by rate limiter
 * @iface: interface for send operation
 * @packet_len: size of packet to send
 *
 * Implements RFC 6762 Section 6 token bucket algorithm. Refills tokens based
 * on elapsed time, consumes tokens if available.
 *
 * Return: true if send allowed, false if rate limited
 */
static bool rate_limiter_check(struct mdns_interface *iface, size_t packet_len)
{
	struct rate_limiter *limiter = rate_limiter_get(iface);
	int64_t now, elapsed, refill;

	if (!limiter)
		return true;

	now = mdns_monotonic_ms();
	elapsed = now - limiter->last_update;

	if (elapsed < 0)
		elapsed = 0;

	/* RFC 6762 Section 6: Token bucket refill */
	refill = elapsed * RATE_LIMITER_RATE / 1000;

	if (refill > RATE_LIMITER_CAPACITY)
		limiter->tokens = RATE_LIMITER_CAPACITY;
	else
		limiter->tokens += (int)refill;

	if (limiter->tokens > RATE_LIMITER_CAPACITY)
		limiter->tokens = RATE_LIMITER_CAPACITY;
	if (limiter->tokens < 0)
		limiter->tokens = 0;

	limiter->last_update = now;

	if (limiter->tokens >= (int)packet_len) {
		limiter->tokens -= packet_len;
		return true;
	}

	return false;
}

/**
 * packet_queue_process() - process queued packets when rate limit allows
 * @t: uloop timeout (unused)
 *
 * Uloop timer callback that attempts to send queued packets. Reschedules
 * itself if queue not empty after processing.
 */
static void packet_queue_process(struct uloop_timeout *t)
{
	struct queued_packet *pkt, *tmp;
	bool queue_empty = true;

	list_for_each_entry_safe(pkt, tmp, &pkt_queue.queue, list) {
		if (!rate_limiter_check(pkt->sock->iface, pkt->len)) {
			queue_empty = false;
			continue;
		}

		if (pkt->sock->fd >= 0)
			sendto(pkt->sock->fd, pkt->data, pkt->len, 0,
			       (struct sockaddr *)&pkt->dest, pkt->dest_len);

		list_del(&pkt->list);
		pkt_queue.bytes -= pkt->len;
		free(pkt->data);
		free(pkt);
	}

	if (pkt_queue.dropped) {
		mdns_info("[queue] Dropped %u packet(s) over the %u byte queue limit\n",
			  pkt_queue.dropped, QUEUE_MAX_BYTES);
		pkt_queue.dropped = 0;
	}

	if (!queue_empty)
		uloop_timeout_set(&pkt_queue.timer, QUEUE_TIMER_INTERVAL);
}

void packet_queue_init(void)
{
	INIT_LIST_HEAD(&pkt_queue.queue);
	pkt_queue.timer.cb = packet_queue_process;
	avl_init(&pkt_queue.limiters, rate_limiter_cmp, false, NULL);
}

void packet_queue_purge(struct mdns_interface *iface)
{
	struct queued_packet *pkt, *tmp;

	list_for_each_entry_safe(pkt, tmp, &pkt_queue.queue, list) {
		if (pkt->sock->iface != iface)
			continue;

		list_del(&pkt->list);
		pkt_queue.bytes -= pkt->len;
		free(pkt->data);
		free(pkt);
	}
}

void packet_queue_flush(void)
{
	struct queued_packet *pkt, *tmp;

	/* Ignores the rate limiter on purpose: the caller is shutting down and
	 * the goodbyes are the last thing this daemon will ever send */
	list_for_each_entry_safe(pkt, tmp, &pkt_queue.queue, list) {
		if (pkt->sock->fd >= 0)
			sendto(pkt->sock->fd, pkt->data, pkt->len, 0,
			       (struct sockaddr *)&pkt->dest, pkt->dest_len);

		list_del(&pkt->list);
		pkt_queue.bytes -= pkt->len;
		free(pkt->data);
		free(pkt);
	}
}

void packet_queue_cleanup(void)
{
	struct queued_packet *pkt, *pkt_tmp;
	struct rate_limiter *limiter, *limiter_tmp;

	uloop_timeout_cancel(&pkt_queue.timer);

	list_for_each_entry_safe(pkt, pkt_tmp, &pkt_queue.queue, list) {
		list_del(&pkt->list);
		free(pkt->data);
		free(pkt);
	}

	pkt_queue.bytes = 0;

	avl_for_each_element_safe(&pkt_queue.limiters, limiter, node, limiter_tmp) {
		avl_delete(&pkt_queue.limiters, &limiter->node);
		free(limiter);
	}
}

bool packet_queue_send(struct mdns_socket *sock, const uint8_t *data, size_t len,
		       struct sockaddr *dest, socklen_t dest_len)
{
	if (!rate_limiter_check(sock->iface, len)) {
		struct queued_packet *pkt;

		if (pkt_queue.bytes + len > QUEUE_MAX_BYTES) {
			pkt_queue.dropped++;
			return false;
		}

		pkt = calloc(1, sizeof(*pkt));
		if (!pkt)
			return false;

		pkt->data = malloc(len);
		if (!pkt->data) {
			free(pkt);
			return false;
		}

		memcpy(pkt->data, data, len);
		pkt->len = len;
		pkt->sock = sock;
		memcpy(&pkt->dest, dest, dest_len);
		pkt->dest_len = dest_len;

		list_add_tail(&pkt->list, &pkt_queue.queue);
		pkt_queue.bytes += len;

		mdns_callback_rate_limit(sock->iface, len);

		if (!pkt_queue.timer.pending)
			uloop_timeout_set(&pkt_queue.timer, QUEUE_TIMER_INTERVAL);

		if (ctx.debug)
			mdns_debug("[queue] Queued %zu byte packet on %s\n", len, sock->iface->name);

		return true;
	}

	return false;
}
