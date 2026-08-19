/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 */

#include <ucode/module.h>
#include "mdns.h"

/**
 * uc_mdns_interface_list() - ucode: mdns.interface_list()
 * @vm: ucode VM
 * @nargs: argument count
 *
 * Returns array of interface objects with name, index, enabled status,
 * and IPv4/IPv6 address lists.
 *
 * Return: ucode array
 */
static uc_value_t *
uc_mdns_interface_list(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *array = ucv_array_new(vm);
	struct mdns_interface *iface;
	char addr_str[INET6_ADDRSTRLEN];

	avl_for_each_element(&ctx.interfaces, iface, node) {
		uc_value_t *obj = ucv_object_new(vm);
		uc_value_t *ipv4_addrs = ucv_array_new(vm);
		uc_value_t *ipv6_addrs = ucv_array_new(vm);

		ucv_object_add(obj, "name", ucv_string_new(iface->name));
		ucv_object_add(obj, "index", ucv_int64_new(iface->ifindex));
		ucv_object_add(obj, "enabled", ucv_boolean_new(iface->enabled));

		/* IPv4 addresses */
		for (int i = 0; i < iface->ipv4.count; i++) {
			inet_ntop(AF_INET, &iface->ipv4.addrs[i], addr_str, sizeof(addr_str));
			ucv_array_push(ipv4_addrs, ucv_string_new(addr_str));
		}
		ucv_object_add(obj, "ipv4_addresses", ipv4_addrs);

		/* IPv6 addresses */
		for (int i = 0; i < iface->ipv6.count; i++) {
			inet_ntop(AF_INET6, &iface->ipv6.addrs[i], addr_str, sizeof(addr_str));
			ucv_array_push(ipv6_addrs, ucv_string_new(addr_str));
		}
		ucv_object_add(obj, "ipv6_addresses", ipv6_addrs);

		ucv_array_push(array, obj);
	}

	return array;
}

/**
 * uc_mdns_interface_create() - ucode: mdns.interface_create(config)
 * @vm: ucode VM
 * @nargs: argument count
 *
 * Creates interface and enables sockets. Config object contains:
 * - name: interface name (required)
 * - ipv4: enable IPv4 (default true)
 * - ipv6: enable IPv6 (default true)
 *
 * Return: interface name string, or NULL on error
 */
static uc_value_t *
uc_mdns_interface_create(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *config = uc_fn_arg(0);
	uc_value_t *name_val, *ipv4_val, *ipv6_val;
	struct mdns_interface *iface;
	const char *name;
	bool ipv4 = true, ipv6 = true;

	if (ucv_type(config) != UC_OBJECT) {
		mdns_set_error("interface_create requires object argument");
		return NULL;
	}

	name_val = ucv_object_get(config, "name", NULL);
	if (ucv_type(name_val) != UC_STRING) {
		mdns_set_error("interface name must be a string");
		return NULL;
	}

	name = ucv_string_get(name_val);

	/* Check if interface already exists */
	if (mdns_interface_get(name)) {
		mdns_set_error("interface %s already exists", name);
		return NULL;
	}

	/* Optional IPv4/IPv6 flags */
	ipv4_val = ucv_object_get(config, "ipv4", NULL);
	if (ipv4_val)
		ipv4 = ucv_is_truish(ipv4_val);

	ipv6_val = ucv_object_get(config, "ipv6", NULL);
	if (ipv6_val)
		ipv6 = ucv_is_truish(ipv6_val);

	/* Create interface */
	iface = mdns_interface_create(name);
	if (!iface)
		return NULL;

	/* Enable interface */
	if (mdns_interface_enable(iface, ipv4, ipv6) < 0) {
		mdns_interface_destroy(iface);
		return NULL;
	}

	return ucv_string_new(name);
}

/**
 * uc_mdns_interface_destroy() - ucode: mdns.interface_destroy(name)
 * @vm: ucode VM
 * @nargs: argument count
 *
 * Destroys interface, closes sockets, releases resources.
 *
 * Return: true on success, false on error
 */
static uc_value_t *
uc_mdns_interface_destroy(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *name_val = uc_fn_arg(0);
	struct mdns_interface *iface;
	const char *name;

	if (ucv_type(name_val) != UC_STRING) {
		mdns_set_error("interface_destroy requires string argument");
		return ucv_boolean_new(false);
	}

	name = ucv_string_get(name_val);
	iface = mdns_interface_get(name);

	if (!iface) {
		mdns_set_error("interface %s not found", name);
		return ucv_boolean_new(false);
	}

	mdns_interface_destroy(iface);

	return ucv_boolean_new(true);
}

/**
 * uc_mdns_packet_parse() - ucode: mdns.packet_parse(buffer)
 * @vm: ucode VM
 * @nargs: argument count
 *
 * Parses DNS packet from wire format string to ucode object.
 *
 * Return: packet object, or NULL on error
 */
static uc_value_t *
uc_mdns_packet_parse(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *buffer = uc_fn_arg(0);
	struct mdns_packet *pkt;
	uc_value_t *result;
	size_t len;
	const char *data;

	if (ucv_type(buffer) != UC_STRING) {
		mdns_set_error("packet_parse requires string buffer argument");
		return NULL;
	}

	data = ucv_string_get(buffer);
	len = ucv_string_length(buffer);

	if (!data || len == 0) {
		mdns_set_error("empty buffer");
		return NULL;
	}

	pkt = mdns_packet_parse((const uint8_t *)data, len);
	if (!pkt)
		return NULL;

	result = mdns_packet_to_ucode(pkt, vm);
	mdns_packet_free(pkt);

	return result;
}

/**
 * uc_mdns_packet_build() - ucode: mdns.packet_build(packet_obj)
 * @vm: ucode VM
 * @nargs: argument count
 *
 * Builds wire format packet from ucode object. Returns string buffer,
 * or array of buffers for future packet-splitting support.
 *
 * Return: buffer string or array of buffers, or NULL on error
 */
static uc_value_t *
uc_mdns_packet_build(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *packet = uc_fn_arg(0);
	uint8_t *buffers[MAX_SPLIT_PACKETS];
	size_t lengths[MAX_SPLIT_PACKETS];
	int count = 0;

	if (mdns_packet_from_ucode(packet, buffers, lengths, &count) < 0)
		return NULL;

	if (count == 0)
		return NULL;

	if (count == 1) {
		uc_value_t *result = ucv_string_new_length((char *)buffers[0], lengths[0]);
		free(buffers[0]);
		return result;
	}

	/* Multiple packets (future: packet splitting) */
	uc_value_t *array = ucv_array_new(vm);
	for (int i = 0; i < count; i++) {
		uc_value_t *buf = ucv_string_new_length((char *)buffers[i], lengths[i]);
		ucv_array_push(array, buf);
		free(buffers[i]);
	}

	return array;
}

/**
 * uc_mdns_cleanup() - ucode: mdns.cleanup()
 * @vm: ucode VM
 * @nargs: argument count
 *
 * Releases the netlink socket, every interface and the packet queue.
 *
 * Return: true
 */
static uc_value_t *
uc_mdns_cleanup(uc_vm_t *vm, size_t nargs)
{
	struct mdns_interface *iface, *tmp;

	avl_for_each_element_safe(&ctx.interfaces, iface, node, tmp)
		mdns_interface_destroy(iface);

	mdns_interface_cleanup();
	packet_queue_cleanup();

	for (int slot = 0; slot < MDNS_CB_MAX; slot++)
		mdns_callback_set(slot, NULL);

	return ucv_boolean_new(true);
}

/**
 * uc_mdns_flush() - ucode: mdns.flush()
 * @vm: ucode VM
 * @nargs: argument count
 *
 * Sends every rate-limited packet still queued, for shutdown.
 *
 * Return: true
 */
static uc_value_t *
uc_mdns_flush(uc_vm_t *vm, size_t nargs)
{
	packet_queue_flush();

	return ucv_boolean_new(true);
}

/**
 * uc_mdns_rdata_encode() - ucode: mdns.rdata_encode(record)
 * @vm: ucode VM
 * @nargs: argument count
 *
 * Encodes the rdata of one record in wire format, with names uncompressed,
 * for the RFC 6762 Section 8.2 lexicographic comparison.
 *
 * Return: byte string, or null on error
 */
static uc_value_t *
uc_mdns_rdata_encode(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *rec = uc_fn_arg(0);
	uint8_t buf[MAX_RDATA_LEN];
	int len;

	if (ucv_type(rec) != UC_OBJECT) {
		mdns_set_error("rdata_encode requires object argument");
		return NULL;
	}

	len = mdns_rdata_encode(rec, buf, sizeof(buf));
	if (len < 0)
		return NULL;

	return ucv_string_new_length((char *)buf, len);
}

/**
 * uc_mdns_packet_send() - ucode: mdns.packet_send(iface_name, packet, dest)
 * @vm: ucode VM
 * @nargs: argument count
 *
 * Sends packet through interface. dest is null for multicast, or object
 * with address, port, family fields for unicast.
 *
 * Return: true on success, false on error
 */
static uc_value_t *
uc_mdns_packet_send(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *iface_name_val = uc_fn_arg(0);
	uc_value_t *packet = uc_fn_arg(1);
	uc_value_t *dest_addr = uc_fn_arg(2);
	struct mdns_interface *iface;
	struct mdns_socket *socks[2];
	int sock_count = 0;
	uint8_t *buffers[MAX_SPLIT_PACKETS];
	size_t lengths[MAX_SPLIT_PACKETS];
	int count = 0;
	const char *iface_name;
	struct sockaddr_storage dest;
	socklen_t dest_len = 0;

	if (ucv_type(iface_name_val) != UC_STRING) {
		mdns_set_error("interface name must be a string");
		return ucv_boolean_new(false);
	}

	iface_name = ucv_string_get(iface_name_val);
	iface = mdns_interface_get(iface_name);

	if (!iface) {
		mdns_set_error("interface %s not found", iface_name);
		return ucv_boolean_new(false);
	}

	/* Build packet */
	if (mdns_packet_from_ucode(packet, buffers, lengths, &count) < 0) {
		for (int i = 0; i < count; i++)
			free(buffers[i]);
		return ucv_boolean_new(false);
	}

	if (count == 0) {
		mdns_set_error("packet_build returned no packets");
		for (int i = 0; i < count; i++)
			free(buffers[i]);
		return ucv_boolean_new(false);
	}

	/* Parse destination address if provided */
	if (dest_addr && ucv_type(dest_addr) != UC_NULL) {
		uc_value_t *addr_val, *port_val, *family_val;
		const char *addr_str, *family_str;
		int port;

		if (ucv_type(dest_addr) != UC_OBJECT) {
			mdns_set_error("dest_addr must be an object or null");
			goto error;
		}

		addr_val = ucv_object_get(dest_addr, "address", NULL);
		port_val = ucv_object_get(dest_addr, "port", NULL);
		family_val = ucv_object_get(dest_addr, "family", NULL);

		if (ucv_type(addr_val) != UC_STRING || ucv_type(family_val) != UC_STRING) {
			mdns_set_error("dest_addr requires address and family strings");
			goto error;
		}

		addr_str = ucv_string_get(addr_val);
		family_str = ucv_string_get(family_val);

		if (port_val) {
			int64_t port_val_int = ucv_int64_get(port_val);
			if (port_val_int < 0 || port_val_int > 65535) {
				mdns_set_error("invalid port number: %lld (must be 0-65535)", (long long)port_val_int);
				goto error;
			}
			port = (int)port_val_int;
		} else {
			port = MDNS_PORT;
		}

		if (strcmp(family_str, "inet") == 0) {
			struct sockaddr_in *sin = (struct sockaddr_in *)&dest;
			memset(sin, 0, sizeof(*sin));
			sin->sin_family = AF_INET;
			sin->sin_port = htons((uint16_t)port);
			if (inet_pton(AF_INET, addr_str, &sin->sin_addr) <= 0) {
				mdns_set_error("invalid IPv4 address: %s", addr_str);
				goto error;
			}
			dest_len = sizeof(*sin);
			/* RFC 6762 Section 6: the source port of all mDNS
			 * responses MUST be 5353, so unicast replies leave
			 * through the port-5353 socket as well */
			socks[sock_count++] = &iface->sockets[MDNS_SOCKET_MCAST_IPV4];
		} else if (strcmp(family_str, "inet6") == 0) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&dest;
			memset(sin6, 0, sizeof(*sin6));
			sin6->sin6_family = AF_INET6;
			sin6->sin6_port = htons((uint16_t)port);
			if (inet_pton(AF_INET6, addr_str, &sin6->sin6_addr) <= 0) {
				mdns_set_error("invalid IPv6 address: %s", addr_str);
				goto error;
			}
			dest_len = sizeof(*sin6);
			socks[sock_count++] = &iface->sockets[MDNS_SOCKET_MCAST_IPV6];
		} else {
			mdns_set_error("unknown address family: %s", family_str);
			goto error;
		}
	} else {
		/* Multicast: send on every open multicast socket so both
		 * address families are served */
		if (iface->sockets[MDNS_SOCKET_MCAST_IPV4].fd >= 0)
			socks[sock_count++] = &iface->sockets[MDNS_SOCKET_MCAST_IPV4];
		if (iface->sockets[MDNS_SOCKET_MCAST_IPV6].fd >= 0)
			socks[sock_count++] = &iface->sockets[MDNS_SOCKET_MCAST_IPV6];

		if (sock_count == 0) {
			mdns_set_error("interface %s has no open sockets", iface_name);
			goto error;
		}
	}

	/* Send packet(s); the IPv4 and IPv6 mDNS domains operate
	 * independently (RFC 6762 Section 20), so a send failure in one
	 * family must not abort the other */
	bool sent_any = false;

	for (int i = 0; i < count; i++) {
		for (int s = 0; s < sock_count; s++) {
			if (mdns_socket_send(socks[s], buffers[i], lengths[i],
					     dest_len ? (struct sockaddr *)&dest : NULL, dest_len) == 0)
				sent_any = true;
		}
		free(buffers[i]);
	}

	return ucv_boolean_new(sent_any);

error:
	for (int i = 0; i < count; i++)
		free(buffers[i]);
	return ucv_boolean_new(false);
}

/**
 * uc_mdns_set_callback() - ucode: mdns.set_callback(event_type, function)
 * @vm: ucode VM
 * @nargs: argument count
 *
 * Registers callback for events: "packet", "interface_change", "rate_limit".
 *
 * Return: true on success, false on error
 */
static uc_value_t *
uc_mdns_set_callback(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *event_type = uc_fn_arg(0);
	uc_value_t *callback = uc_fn_arg(1);
	const char *type_str;

	if (ucv_type(event_type) != UC_STRING) {
		mdns_set_error("event_type must be a string");
		return ucv_boolean_new(false);
	}

	if (!ucv_is_callable(callback)) {
		mdns_set_error("callback must be a function");
		return ucv_boolean_new(false);
	}

	type_str = ucv_string_get(event_type);

	if (strcmp(type_str, "packet") == 0)
		mdns_callback_set(MDNS_CB_PACKET, callback);
	else if (strcmp(type_str, "interface_change") == 0)
		mdns_callback_set(MDNS_CB_INTERFACE_CHANGE, callback);
	else if (strcmp(type_str, "rate_limit") == 0)
		mdns_callback_set(MDNS_CB_RATE_LIMIT, callback);
	else {
		mdns_set_error("unknown event type: %s", type_str);
		return ucv_boolean_new(false);
	}

	return ucv_boolean_new(true);
}

/**
 * uc_mdns_set_hostname() - ucode: mdns.set_hostname(hostname)
 * @vm: ucode VM
 * @nargs: argument count
 *
 * Sets local hostname for mDNS responses.
 *
 * Return: true on success, false on error
 */
static uc_value_t *
uc_mdns_set_hostname(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *hostname = uc_fn_arg(0);

	if (ucv_type(hostname) != UC_STRING) {
		mdns_set_error("hostname must be a string");
		return ucv_boolean_new(false);
	}

	free(ctx.hostname);
	ctx.hostname = strdup(ucv_string_get(hostname));
	if (!ctx.hostname) {
		mdns_set_error("Out of memory");
		return ucv_boolean_new(false);
	}

	return ucv_boolean_new(true);
}

/**
 * uc_mdns_error() - ucode: mdns.error()
 * @vm: ucode VM
 * @nargs: argument count
 *
 * Returns last error message from global context.
 *
 * Return: error string
 */
static uc_value_t *
uc_mdns_error(uc_vm_t *vm, size_t nargs)
{
	return ucv_string_new(ctx.error);
}

/**
 * uc_mdns_set_debug() - ucode: mdns.set_debug(enabled)
 * @vm: ucode VM
 * @nargs: argument count
 *
 * Enables or disables info logging to stdout (cfg.debug).
 *
 * Return: true
 */
static uc_value_t *
uc_mdns_set_debug(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *enabled = uc_fn_arg(0);

	ctx.debug = ucv_is_truish(enabled);

	return ucv_boolean_new(true);
}

/**
 * uc_mdns_set_trace() - ucode: mdns.set_trace(enabled)
 * @vm: ucode VM
 * @nargs: argument count
 *
 * Enables or disables debug logging to stdout (cfg.trace).
 *
 * Return: true
 */
static uc_value_t *
uc_mdns_set_trace(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *enabled = uc_fn_arg(0);

	mdns_set_trace(ucv_is_truish(enabled));

	return ucv_boolean_new(true);
}

/**
 * uc_mdns_info() - ucode: mdns.info(message)
 * @vm: ucode VM
 * @nargs: argument count
 *
 * Prints info message to stdout if cfg.debug enabled.
 * Accepts a single string argument (use template literals in ucode for formatting).
 *
 * Return: null
 */
static uc_value_t *
uc_mdns_info(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *msg_val = uc_fn_arg(0);
	const char *msg;

	if (ucv_type(msg_val) != UC_STRING) {
		mdns_set_error("info requires string argument");
		return NULL;
	}

	if (!ctx.debug)
		return NULL;

	msg = ucv_string_get(msg_val);
	mdns_info("%s", msg);

	return NULL;
}

/**
 * uc_mdns_debug() - ucode: mdns.debug(message)
 * @vm: ucode VM
 * @nargs: argument count
 *
 * Prints debug message to stdout if cfg.trace enabled.
 * Accepts a single string argument (use template literals in ucode for formatting).
 *
 * Return: null
 */
static uc_value_t *
uc_mdns_debug(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *msg_val = uc_fn_arg(0);
	const char *msg;

	if (ucv_type(msg_val) != UC_STRING) {
		mdns_set_error("debug requires string argument");
		return NULL;
	}

	if (!ctx.trace)
		return NULL;

	msg = ucv_string_get(msg_val);
	mdns_debug("%s", msg);

	return NULL;
}

static const uc_function_list_t mdns_fns[] = {
	{ "interface_list",	uc_mdns_interface_list },
	{ "interface_create",	uc_mdns_interface_create },
	{ "interface_destroy",	uc_mdns_interface_destroy },
	{ "packet_parse",	uc_mdns_packet_parse },
	{ "packet_build",	uc_mdns_packet_build },
	{ "rdata_encode",	uc_mdns_rdata_encode },
	{ "flush",		uc_mdns_flush },
	{ "cleanup",		uc_mdns_cleanup },
	{ "packet_send",	uc_mdns_packet_send },
	{ "set_callback",	uc_mdns_set_callback },
	{ "set_hostname",	uc_mdns_set_hostname },
	{ "set_debug",		uc_mdns_set_debug },
	{ "set_trace",		uc_mdns_set_trace },
	{ "info",		uc_mdns_info },
	{ "debug",		uc_mdns_debug },
	{ "error",		uc_mdns_error },
};

/**
 * uc_module_init() - ucode module initialisation
 * @vm: ucode VM
 * @scope: module scope object
 *
 * Registers all mdns module functions and constants, stores VM context,
 * initialises interface monitoring subsystem.
 */
void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, mdns_fns);

	/* Register constants */
	ucv_object_add(scope, "TYPE_A", ucv_int64_new(DNS_TYPE_A));
	ucv_object_add(scope, "TYPE_NS", ucv_int64_new(DNS_TYPE_NS));
	ucv_object_add(scope, "TYPE_CNAME", ucv_int64_new(DNS_TYPE_CNAME));
	ucv_object_add(scope, "TYPE_PTR", ucv_int64_new(DNS_TYPE_PTR));
	ucv_object_add(scope, "TYPE_TXT", ucv_int64_new(DNS_TYPE_TXT));
	ucv_object_add(scope, "TYPE_AAAA", ucv_int64_new(DNS_TYPE_AAAA));
	ucv_object_add(scope, "TYPE_SRV", ucv_int64_new(DNS_TYPE_SRV));
	ucv_object_add(scope, "TYPE_OPT", ucv_int64_new(DNS_TYPE_OPT));
	ucv_object_add(scope, "TYPE_NSEC", ucv_int64_new(DNS_TYPE_NSEC));
	ucv_object_add(scope, "TYPE_ANY", ucv_int64_new(DNS_TYPE_ANY));

	ucv_object_add(scope, "CLASS_IN", ucv_int64_new(DNS_CLASS_IN));
	ucv_object_add(scope, "CLASS_ANY", ucv_int64_new(DNS_CLASS_ANY));

	ucv_object_add(scope, "MCAST_ADDR_IPV4", ucv_string_new(MDNS_MCAST_ADDR_IPV4));
	ucv_object_add(scope, "MCAST_ADDR_IPV6", ucv_string_new(MDNS_MCAST_ADDR_IPV6));
	ucv_object_add(scope, "MCAST_PORT", ucv_int64_new(MDNS_PORT));

	/* Store VM context */
	ctx.vm = vm;

	/* Initialize subsystems */
	packet_queue_init();
	mdns_interface_init();
	mdns_callbacks_init(vm);
}
