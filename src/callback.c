/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 */

#include <string.h>
#include <stdlib.h>
#include <libubox/ulog.h>
#include "mdns.h"

void mdns_callbacks_init(uc_vm_t *vm)
{
	ctx.callbacks = ucv_resource_create_ex(vm, NULL, NULL, MDNS_CB_MAX, 0);

	if (ctx.callbacks)
		ucv_resource_persistent_set(ctx.callbacks, true);
}

uc_value_t *mdns_callback_get(enum mdns_callback_slot slot)
{
	if (!ctx.callbacks || slot >= MDNS_CB_MAX)
		return NULL;

	return ucv_resource_value_get(ctx.callbacks, slot);
}

bool mdns_callback_set(enum mdns_callback_slot slot, uc_value_t *fn)
{
	if (!ctx.callbacks || slot >= MDNS_CB_MAX)
		return false;

	return ucv_resource_value_set(ctx.callbacks, slot, ucv_get(fn));
}

/**
 * exception_guard_invoke() - hand a pending exception to uloop.guard()
 *
 * The handler installed by uloop.guard() lives in the VM registry under
 * "uloop.ex_handler". uloop calls it for exceptions raised in its own
 * callbacks; ours come from a socket or netlink handler and reach it here.
 *
 * Return: true if the handler ran
 */
static bool exception_guard_invoke(void)
{
	uc_value_t *handler, *exception;

	handler = uc_vm_registry_get(ctx.vm, "uloop.ex_handler");

	if (!ucv_is_callable(handler))
		return false;

	exception = uc_vm_exception_object(ctx.vm);

	uc_vm_stack_push(ctx.vm, ucv_get(handler));
	uc_vm_stack_push(ctx.vm, exception);

	if (uc_vm_call(ctx.vm, false, 1) != EXCEPTION_NONE)
		return false;

	ucv_put(uc_vm_stack_pop(ctx.vm));

	return true;
}

/**
 * invoke_callback_internal() - centralised callback invocation with proper cleanup
 * @callback: ucode callback function to invoke
 * @callback_name: name of callback for debug messages (or NULL)
 * @return_value: if true, return callback result; if false, discard it
 * @nargs: number of arguments
 * @ap: va_list of arguments (uc_value_t *)
 *
 * Invokes ucode callback with proper reference counting and exception handling.
 * Handles cleanup of all arguments. Arguments are consumed by this function.
 *
 * Return: callback return value if return_value=true (caller must ucv_put), NULL otherwise
 */
static uc_value_t *invoke_callback_internal(uc_value_t *callback, const char *callback_name,
					     bool return_value, size_t nargs, va_list ap)
{
	uc_value_t *args[nargs];
	uc_value_t *rv = NULL;
	size_t i;

	if (!callback || !ctx.vm) {
		/* Clean up args even if callback not invoked */
		for (i = 0; i < nargs; i++)
			ucv_put(va_arg(ap, uc_value_t *));
		return NULL;
	}

	/* Collect arguments from va_list */
	for (i = 0; i < nargs; i++)
		args[i] = va_arg(ap, uc_value_t *);

	/* Push callback and arguments to stack with incremented refcount */
	uc_vm_stack_push(ctx.vm, ucv_get(callback));
	for (i = 0; i < nargs; i++)
		uc_vm_stack_push(ctx.vm, args[i] ? ucv_get(args[i]) : NULL);

	/* Invoke callback and handle all exception types */
	switch (uc_vm_call(ctx.vm, false, nargs)) {
	case EXCEPTION_NONE:
		rv = uc_vm_stack_pop(ctx.vm);
		if (!return_value) {
			ucv_put(rv);
			rv = NULL;
		}
		break;

	case EXCEPTION_EXIT:
		/* Clean up and exit as requested */
		for (i = 0; i < nargs; i++)
			ucv_put(args[i]);
		exit(ctx.vm->arg.s32);
		break;

	default:
		if (exception_guard_invoke())
			break;

		/* Other exceptions (SYNTAX, TYPE, REFERENCE, etc.) */
		ulog(LOG_ERR, "callback: Exception: %s\n",
			ctx.vm->exception.type == EXCEPTION_SYNTAX ? "SYNTAX" :
			ctx.vm->exception.type == EXCEPTION_RUNTIME ? "RUNTIME" :
			ctx.vm->exception.type == EXCEPTION_TYPE ? "TYPE" :
			ctx.vm->exception.type == EXCEPTION_REFERENCE ? "REFERENCE" :
			ctx.vm->exception.type == EXCEPTION_USER ? "USER" :
			"UNKNOWN");
		if (ctx.vm->exception.message)
			ulog(LOG_ERR, "callback: Exception message: %s\n",
				ctx.vm->exception.message);
		if (ctx.vm->exception.stacktrace) {
			char *trace = ucv_to_string(NULL, ctx.vm->exception.stacktrace);
			ulog(LOG_ERR, "callback: Stack trace:\n%s\n", trace);
			free(trace);
		}
		rv = NULL;
		break;
	}

	/* Clean up original argument references */
	for (i = 0; i < nargs; i++)
		ucv_put(args[i]);

	return rv;
}

/**
 * invoke_callback() - invoke callback and discard return value
 * @callback: ucode callback function
 * @callback_name: callback name for debugging
 * @nargs: number of arguments
 * @...: variable arguments (uc_value_t *)
 *
 * Wrapper around invoke_callback_internal() that discards return value.
 */
static void invoke_callback(uc_value_t *callback, const char *callback_name, size_t nargs, ...)
{
	va_list ap;

	va_start(ap, nargs);
	invoke_callback_internal(callback, callback_name, false, nargs, ap);
	va_end(ap);
}

/**
 * invoke_callback_with_return() - invoke callback and return result
 * @callback: ucode callback function
 * @callback_name: callback name for debugging
 * @nargs: number of arguments
 * @...: variable arguments (uc_value_t *)
 *
 * Wrapper around invoke_callback_internal() that returns callback result.
 *
 * Return: callback return value (caller must ucv_put), or NULL on error
 */
static uc_value_t *invoke_callback_with_return(uc_value_t *callback, const char *callback_name, size_t nargs, ...)
{
	va_list ap;
	uc_value_t *rv;

	va_start(ap, nargs);
	rv = invoke_callback_internal(callback, callback_name, true, nargs, ap);
	va_end(ap);

	return rv;
}

/**
 * mdns_callback_packet() - invoke on_packet ucode callback
 * @iface: interface packet received on
 * @pkt: parsed packet
 * @from: source address
 * @multicast: true if received on multicast socket
 * @is_legacy: true if legacy unicast query (source port != 5353)
 *
 * Converts packet and metadata to ucode objects, invokes registered
 * on_packet callback function if set.
 */
void mdns_callback_packet(struct mdns_interface *iface, struct mdns_packet *pkt,
			   struct sockaddr_storage *from, bool multicast, bool is_legacy)
{
	uc_value_t *pkt_obj, *from_obj, *iface_obj;
	char addr_str[INET6_ADDRSTRLEN];

	if (!mdns_callback_get(MDNS_CB_PACKET) || !ctx.vm)
		return;

	/* Convert packet to ucode object */
	pkt_obj = mdns_packet_to_ucode(pkt, ctx.vm);
	if (!pkt_obj)
		return;

	/* Build source address object */
	from_obj = ucv_object_new(ctx.vm);
	if (!from_obj) {
		ucv_put(pkt_obj);
		return;
	}

	if (from->ss_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)from;
		inet_ntop(AF_INET, &sin->sin_addr, addr_str, sizeof(addr_str));
		ucv_object_add(from_obj, "address", ucv_string_new(addr_str));
		ucv_object_add(from_obj, "port", ucv_int64_new(ntohs(sin->sin_port)));
		ucv_object_add(from_obj, "family", ucv_string_new("inet"));
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)from;
		inet_ntop(AF_INET6, &sin6->sin6_addr, addr_str, sizeof(addr_str));
		ucv_object_add(from_obj, "address", ucv_string_new(addr_str));
		ucv_object_add(from_obj, "port", ucv_int64_new(ntohs(sin6->sin6_port)));
		ucv_object_add(from_obj, "family", ucv_string_new("inet6"));
	}

	/* Build interface object */
	iface_obj = ucv_object_new(ctx.vm);
	if (!iface_obj) {
		ucv_put(pkt_obj);
		ucv_put(from_obj);
		return;
	}

	ucv_object_add(iface_obj, "name", ucv_string_new(iface->name));
	ucv_object_add(iface_obj, "index", ucv_int64_new(iface->ifindex));

	/* Invoke callback with proper cleanup via centralised helper */
	invoke_callback(mdns_callback_get(MDNS_CB_PACKET), "on_packet", 5,
			pkt_obj,
			from_obj,
			iface_obj,
			ucv_boolean_new(multicast),
			ucv_boolean_new(is_legacy));
}

/**
 * mdns_callback_interface_change() - invoke on_interface_change ucode callback
 * @iface: interface that changed
 * @event: event type (up/down/addr_add/addr_del)
 *
 * Converts interface state to ucode object, invokes registered
 * on_interface_change callback function if set.
 */
void mdns_callback_interface_change(struct mdns_interface *iface,
				    enum mdns_interface_event event)
{
	uc_value_t *iface_obj, *addrs_v4, *addrs_v6;
	char addr_str[INET6_ADDRSTRLEN];
	const char *event_str;

	if (!mdns_callback_get(MDNS_CB_INTERFACE_CHANGE) || !ctx.vm)
		return;

	/* Build interface object */
	iface_obj = ucv_object_new(ctx.vm);
	if (!iface_obj)
		return;

	ucv_object_add(iface_obj, "name", ucv_string_new(iface->name));
	ucv_object_add(iface_obj, "index", ucv_int64_new(iface->ifindex));
	ucv_object_add(iface_obj, "enabled", ucv_boolean_new(iface->enabled));

	/* Add IPv4 addresses */
	addrs_v4 = ucv_array_new(ctx.vm);
	for (int i = 0; i < iface->ipv4.count; i++) {
		inet_ntop(AF_INET, &iface->ipv4.addrs[i], addr_str, sizeof(addr_str));
		ucv_array_push(addrs_v4, ucv_string_new(addr_str));
	}
	ucv_object_add(iface_obj, "ipv4_addresses", addrs_v4);

	/* Add IPv6 addresses */
	addrs_v6 = ucv_array_new(ctx.vm);
	for (int i = 0; i < iface->ipv6.count; i++) {
		inet_ntop(AF_INET6, &iface->ipv6.addrs[i], addr_str, sizeof(addr_str));
		ucv_array_push(addrs_v6, ucv_string_new(addr_str));
	}
	ucv_object_add(iface_obj, "ipv6_addresses", addrs_v6);

	/* Event string */
	switch (event) {
	case MDNS_IFACE_UP:
		event_str = "up";
		break;
	case MDNS_IFACE_DOWN:
		event_str = "down";
		break;
	case MDNS_IFACE_ADDR_ADD:
		event_str = "addr_add";
		break;
	case MDNS_IFACE_ADDR_DEL:
		event_str = "addr_del";
		break;
	default:
		event_str = "unknown";
		break;
	}

	/* Invoke callback with proper cleanup via centralised helper */
	invoke_callback(mdns_callback_get(MDNS_CB_INTERFACE_CHANGE), "on_interface_change", 2,
			iface_obj,
			ucv_string_new(event_str));
}

/**
 * mdns_callback_rate_limit() - invoke on_rate_limit ucode callback
 * @iface: interface for send operation
 * @packet_len: size of packet to send
 *
 * Queries ucode layer whether send should proceed based on rate limiting.
 * If no callback registered, allows send by default.
 *
 * Return: true if send allowed, false if rate limited
 */
bool mdns_callback_rate_limit(struct mdns_interface *iface, size_t packet_len)
{
	uc_value_t *iface_obj, *result;
	bool allow = true;

	if (!mdns_callback_get(MDNS_CB_RATE_LIMIT) || !ctx.vm)
		return true;  /* No callback, allow by default */

	/* Build interface object */
	iface_obj = ucv_object_new(ctx.vm);
	if (!iface_obj)
		return true;  /* Allocation failure, allow by default */

	ucv_object_add(iface_obj, "name", ucv_string_new(iface->name));
	ucv_object_add(iface_obj, "index", ucv_int64_new(iface->ifindex));

	/* Invoke callback and get return value */
	result = invoke_callback_with_return(mdns_callback_get(MDNS_CB_RATE_LIMIT), "on_rate_limit", 2,
					     iface_obj,
					     ucv_int64_new(packet_len));

	if (result) {
		allow = ucv_is_truish(result);
		ucv_put(result);
	} else {
		/* Exception or error, allow by default */
		allow = true;
	}

	return allow;
}
