/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "mdns.h"

/**
 * ctx - global mDNS daemon context
 *
 * Contains interface tree, netlink socket, ucode callbacks, VM context,
 * error message buffer, and configuration.
 */
struct mdns_ctx ctx = {
	.interfaces = AVL_TREE_INIT(ctx.interfaces, avl_strcmp, false, NULL),
};

static const struct {
	uint16_t type;
	const char *str;
} type_strings[] = {
	{ DNS_TYPE_A, "A" },
	{ DNS_TYPE_NS, "NS" },
	{ DNS_TYPE_CNAME, "CNAME" },
	{ DNS_TYPE_PTR, "PTR" },
	{ DNS_TYPE_TXT, "TXT" },
	{ DNS_TYPE_AAAA, "AAAA" },
	{ DNS_TYPE_SRV, "SRV" },
	{ DNS_TYPE_OPT, "OPT" },
	{ DNS_TYPE_NSEC, "NSEC" },
	{ DNS_TYPE_ANY, "ANY" },
};

/**
 * mdns_type_to_string() - convert DNS type to string
 * @type: DNS type value
 *
 * Return: type name string (e.g. "A", "PTR"), or "UNKNOWN"
 */
const char *mdns_type_to_string(uint16_t type)
{
	static char unknown_buf[32];

	for (size_t i = 0; i < ARRAY_SIZE(type_strings); i++) {
		if (type_strings[i].type == type)
			return type_strings[i].str;
	}

	snprintf(unknown_buf, sizeof(unknown_buf), "UNKNOWN_%u", type);
	return unknown_buf;
}

/**
 * mdns_string_to_type() - convert string to DNS type
 * @str: type name string
 *
 * Case-insensitive lookup.
 *
 * Return: DNS type value, or -1 if unknown
 */
int mdns_string_to_type(const char *str)
{
	for (size_t i = 0; i < ARRAY_SIZE(type_strings); i++) {
		if (strcasecmp(type_strings[i].str, str) == 0)
			return type_strings[i].type;
	}
	return -1;
}

/**
 * mdns_class_to_string() - convert DNS class to string
 * @class: DNS class value (cache-flush bit masked off)
 *
 * Return: class name string (e.g. "IN", "ANY"), or "UNKNOWN"
 */
const char *mdns_class_to_string(uint16_t class)
{
	switch (class & ~DNS_CLASS_FLUSH) {
	case DNS_CLASS_IN:
		return "IN";
	case DNS_CLASS_ANY:
		return "ANY";
	default:
		return "UNKNOWN";
	}
}

/**
 * mdns_monotonic_ms() - milliseconds from a clock that never steps
 *
 * Return: milliseconds since an unspecified epoch
 */
int64_t mdns_monotonic_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/**
 * mdns_set_error() - set global error message
 * @fmt: printf-style format string
 * @...: format arguments
 *
 * Stores formatted error message in global context for retrieval by ucode.
 */
void mdns_set_error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(ctx.error, sizeof(ctx.error), fmt, ap);
	va_end(ap);
}

/**
 * mdns_info() - output info message to stderr
 * @fmt: printf-style format string
 * @...: format arguments
 *
 * Prints info message to stderr if cfg.debug enabled (ctx.debug).
 * stderr, not stdout, because procd forwards only stderr to syslog.
 */
void mdns_info(const char *fmt, ...)
{
	va_list ap;

	if (!ctx.debug)
		return;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fflush(stderr);
}

/**
 * mdns_debug() - output debug message to stderr
 * @fmt: printf-style format string
 * @...: format arguments
 *
 * Prints debug message to stderr if cfg.trace enabled (ctx.trace).
 */
void mdns_debug(const char *fmt, ...)
{
	va_list ap;

	if (!ctx.trace)
		return;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fflush(stderr);
}

/**
 * mdns_set_trace() - set trace flag
 * @enabled: true to enable trace output, false to disable
 *
 * Sets ctx.trace flag to control mdns_debug() output.
 */
void mdns_set_trace(bool enabled)
{
	ctx.trace = enabled;
}
