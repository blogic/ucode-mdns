/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 */

#ifndef __MDNS_H
#define __MDNS_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libubox/uloop.h>
#include <libubox/avl.h>
#include <libubox/avl-cmp.h>
#include <libubox/list.h>
#include <ucode/types.h>
#include <ucode/vm.h>

/* DNS Constants */
#define MDNS_PORT		5353
#define MDNS_MCAST_ADDR_IPV4	"224.0.0.251"
#define MDNS_MCAST_ADDR_IPV6	"ff02::fb"

/* RFC 6762 Section 18: DNS Header Flags */
#define DNS_FLAG_RESPONSE	0x8000  /* QR bit - Section 18.2 */
#define DNS_FLAG_AUTHORITATIVE	0x0400  /* AA bit - Section 18.4 */
#define DNS_FLAG_TRUNCATED	0x0200  /* TC bit - Section 18.5 */
#define DNS_FLAG_RD		0x0100  /* RD bit - Section 18.6 */
#define DNS_FLAG_RA		0x0080  /* RA bit - Section 18.7 */
#define DNS_FLAG_Z		0x0040  /* Z bit - Section 18.8 (MUST be zero) */
#define DNS_FLAG_AD		0x0020  /* AD bit - Section 18.9 (MUST be zero) */
#define DNS_FLAG_CD		0x0010  /* CD bit - Section 18.10 (MUST be zero) */

#define DNS_OPCODE_MASK		0x7800  /* Section 18.3 */
#define DNS_OPCODE_SHIFT	11
#define DNS_RCODE_MASK		0x000F  /* Section 18.11 */

/* RFC 6762 Section 18.8-18.10: Reserved bits that MUST be zero */
#define DNS_RESERVED_BITS	(DNS_FLAG_Z | DNS_FLAG_AD | DNS_FLAG_CD)

#define DNS_TYPE_A		1
#define DNS_TYPE_NS		2
#define DNS_TYPE_CNAME		5
#define DNS_TYPE_PTR		12
#define DNS_TYPE_TXT		16
#define DNS_TYPE_AAAA		28
#define DNS_TYPE_SRV		33
#define DNS_TYPE_OPT		41
#define DNS_TYPE_NSEC		47
#define DNS_TYPE_ANY		255

#define DNS_CLASS_IN		1
#define DNS_CLASS_ANY		255
#define DNS_CLASS_FLUSH		0x8000
#define DNS_CLASS_UNICAST	0x8000

#define MAX_NAME_LEN		255
#define MAX_LABEL_LEN		63
#define MAX_PACKET_SIZE		9000
/* RFC 6762 Section 17: keep a packet under the Ethernet MTU whenever it can
 * be done, and split into further packets rather than rely on IP fragments */
#define SOFT_PACKET_SIZE	1400
/* Packets one call to mdns.packet_send() may split into */
#define MAX_SPLIT_PACKETS	16
#define MAX_RDATA_LEN		8192
#define MAX_TXT_STRINGS		100	/* DoS prevention limit */

/* Smallest wire encoding: a root or fully compressed name plus the fixed
 * fields. Used to bound the declared section counts against the packet. */
#define DNS_QUESTION_MIN_SIZE	5
#define DNS_RECORD_MIN_SIZE	11

/* DNS wire format structures */
struct dns_header {
	uint16_t id;
	uint16_t flags;
	uint16_t questions;
	uint16_t answers;
	uint16_t authority;
	uint16_t additional;
} __attribute__((packed));

struct dns_question {
	uint16_t type;
	uint16_t class;
} __attribute__((packed));

struct dns_answer {
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlength;
} __attribute__((packed));

struct dns_srv_data {
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
} __attribute__((packed));

/* Parsed DNS record representation (before ucode conversion) */
struct mdns_record {
	char *name;
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	bool flush_cache;

	union {
		struct {
			struct in_addr addr;
		} a;
		struct {
			struct in6_addr addr;
		} aaaa;
		struct {
			char *name;
		} ptr;
		struct {
			uint16_t priority;
			uint16_t weight;
			uint16_t port;
			char *target;
		} srv;
		struct {
			char **strings;
			int count;
		} txt;
		struct {
			char *name;
		} cname;
		struct {
			uint8_t *data;
			uint16_t len;
		} raw;
	} rdata;
};

struct mdns_question {
	char *name;
	uint16_t type;
	uint16_t class;
	bool unicast_response;
};

struct mdns_packet {
	struct dns_header header;

	struct mdns_question *questions;
	int question_count;

	struct mdns_record *answers;
	int answer_count;

	struct mdns_record *authority;
	int authority_count;

	struct mdns_record *additional;
	int additional_count;
};

/* Interface management */
enum mdns_socket_type {
	MDNS_SOCKET_MCAST_IPV4 = 0,
	MDNS_SOCKET_MCAST_IPV6 = 1,
	MDNS_SOCKET_MAX
};

enum mdns_interface_event {
	MDNS_IFACE_UP,
	MDNS_IFACE_DOWN,
	MDNS_IFACE_ADDR_ADD,
	MDNS_IFACE_ADDR_DEL
};

struct mdns_socket {
	int fd;
	struct uloop_fd ufd;
	enum mdns_socket_type type;
	struct mdns_interface *iface;
};

struct mdns_interface {
	struct avl_node node;

	char *name;
	int ifindex;
	bool enabled;

	/* Requested families, replayed when the link or an address appears
	 * after the interface was created */
	bool want_ipv4;
	bool want_ipv6;

	struct mdns_socket sockets[MDNS_SOCKET_MAX];

	/* Interface addresses and netmasks */
	struct {
		struct in_addr *addrs;
		struct in_addr *netmasks;
		int count;
	} ipv4;

	struct {
		struct in6_addr *addrs;
		uint8_t *prefixlens;  /* IPv6 uses prefix length, not netmask */
		int count;
	} ipv6;

	/* Rate limiting */
	struct {
		time_t last_send;
		int tokens;
	} ratelimit;
};

/* Global state */
struct mdns_ctx {
	struct avl_tree interfaces;
	struct uloop_fd netlink_fd;

	/* Callbacks from ucode */
	/* Callbacks live in the slots of a persistent resource so the garbage
	 * collector can reach them. A value held only by a C structure is not
	 * marked and is swept whatever its reference count. */
	uc_value_t *callbacks;

	/* Ucode VM context */
	uc_vm_t *vm;

	/* Last error message */
	char error[256];

	/* Configuration */
	char *hostname;
	bool ipv4_enabled;
	bool ipv6_enabled;
	bool debug;
	bool trace;
};

extern struct mdns_ctx ctx;

/* packet.c - DNS packet high-level functions */

/**
 * mdns_packet_parse() - parse DNS packet from wire format
 * @data: pointer to packet data
 * @len: length of packet data
 *
 * Parses DNS packet from wire format into internal representation.
 * Validates RFC 6762 Section 18.3 (OPCODE=0) and Section 18.11 (RCODE=0).
 * Handles DNS name compression using dn_expand().
 *
 * Return: pointer to parsed packet structure, or NULL on error
 */
struct mdns_packet *mdns_packet_parse(const uint8_t *data, size_t len);

/**
 * mdns_packet_free() - free parsed packet structure
 * @pkt: packet to free
 *
 * Releases all memory associated with parsed packet, including
 * dynamically allocated names, rdata, and section arrays.
 */
void mdns_packet_free(struct mdns_packet *pkt);

/**
 * mdns_packet_to_ucode() - convert parsed packet to ucode object
 * @pkt: parsed packet structure
 * @vm: ucode VM context
 *
 * Converts internal packet representation to ucode object suitable
 * for passing to ucode business logic callbacks.
 *
 * Return: ucode object, or NULL on error
 */
uc_value_t *mdns_packet_to_ucode(struct mdns_packet *pkt, uc_vm_t *vm);

/* parse.c */
int parse_question(const uint8_t *base, size_t base_len, const uint8_t **ptr,
		   size_t *remaining, struct mdns_question *q);
int parse_record(const uint8_t *base, size_t base_len, const uint8_t **ptr,
		 size_t *remaining, struct mdns_record *rec);

/* build.c */

/**
 * mdns_packet_from_ucode() - build wire format packet from ucode object
 * @val: ucode packet object
 * @buffers: output array of packet buffers
 * @lengths: output array of packet lengths
 * @count: output number of packets generated
 *
 * Converts ucode packet object to wire format DNS packet(s).
 * May generate multiple packets for future packet-splitting support.
 * Uses dn_comp() for DNS name compression.
 *
 * Return: 0 on success, -1 on error
 */
int mdns_packet_from_ucode(uc_value_t *val, uint8_t **buffers, size_t *lengths, int *count);

/**
 * mdns_rdata_encode() - encode a record's rdata on its own
 * @rec: ucode record object
 * @buf: output buffer
 * @size: size of @buf
 *
 * Return: number of bytes written, or -1 on error
 */
int mdns_rdata_encode(uc_value_t *rec, uint8_t *buf, size_t size);

/* socket.c - Socket management */

/**
 * mdns_socket_open() - open and configure mDNS socket
 * @iface: interface to bind socket to
 * @type: socket type (multicast/unicast, IPv4/IPv6)
 *
 * Creates socket, joins multicast groups, sets socket options.
 * Registers socket with uloop for event handling.
 *
 * Return: 0 on success, -1 on error
 */
int mdns_socket_open(struct mdns_interface *iface, enum mdns_socket_type type);

/**
 * mdns_socket_close() - close socket and cleanup
 * @sock: socket to close
 *
 * Removes socket from uloop, closes file descriptor, resets state.
 */
void mdns_socket_close(struct mdns_socket *sock);

/**
 * mdns_socket_send() - send packet through socket
 * @sock: socket to send through
 * @data: packet data
 * @len: packet length
 * @dest: destination address (NULL for multicast)
 * @dest_len: destination address length
 *
 * Sends packet through socket, applying rate limiting.
 * Automatically selects multicast destination if dest is NULL.
 *
 * Return: 0 on success, -1 on error
 */
int mdns_socket_send(struct mdns_socket *sock, const uint8_t *data, size_t len,
		     struct sockaddr *dest, socklen_t dest_len);

/* interface.c - Interface monitoring and management */

/**
 * mdns_interface_init() - initialise interface monitoring subsystem
 *
 * Creates netlink socket for monitoring interface and address changes.
 * Registers socket with uloop for event handling.
 *
 * Return: 0 on success, -1 on error
 */
int mdns_interface_init(void);

/**
 * mdns_interface_cleanup() - shutdown interface monitoring
 *
 * Destroys all interfaces, closes netlink socket, releases resources.
 */
void mdns_interface_cleanup(void);

/**
 * mdns_interface_create() - create interface object
 * @name: interface name (e.g. "eth0")
 *
 * Allocates and initialises interface structure, adds to global tree.
 * Does not enable sockets - call mdns_interface_enable() separately.
 *
 * Return: pointer to interface, or NULL on error
 */
struct mdns_interface *mdns_interface_create(const char *name);

/**
 * mdns_interface_destroy() - destroy interface object
 * @iface: interface to destroy
 *
 * Disables interface, closes sockets, releases memory, removes from tree.
 */
void mdns_interface_destroy(struct mdns_interface *iface);

/**
 * mdns_interface_get() - lookup interface by name
 * @name: interface name
 *
 * Return: pointer to interface, or NULL if not found
 */
struct mdns_interface *mdns_interface_get(const char *name);

/**
 * mdns_interface_enable() - enable mDNS on interface
 * @iface: interface to enable
 * @ipv4: enable IPv4 sockets
 * @ipv6: enable IPv6 sockets
 *
 * Updates interface addresses, opens requested sockets, joins multicast groups.
 *
 * Return: 0 on success, -1 on error
 */
int mdns_interface_enable(struct mdns_interface *iface, bool ipv4, bool ipv6);

/**
 * mdns_interface_disable() - disable mDNS on interface
 * @iface: interface to disable
 *
 * Closes all sockets, marks interface as disabled.
 */
void mdns_interface_disable(struct mdns_interface *iface);

/**
 * mdns_interface_update_addrs() - refresh interface address list
 * @iface: interface to update
 *
 * Queries current IPv4/IPv6 addresses via getifaddrs(), updates interface state.
 */
void mdns_interface_update_addrs(struct mdns_interface *iface);

/* util.c - Utility functions */

/**
 * mdns_type_to_string() - convert DNS type to string
 * @type: DNS type value
 *
 * Return: type name string (e.g. "A", "PTR"), or "UNKNOWN"
 */
const char *mdns_type_to_string(uint16_t type);

/**
 * mdns_string_to_type() - convert string to DNS type
 * @str: type name string
 *
 * Return: DNS type value, or -1 if unknown
 */
int mdns_string_to_type(const char *str);

/**
 * mdns_class_to_string() - convert DNS class to string
 * @class: DNS class value
 *
 * Return: class name string (e.g. "IN", "ANY"), or "UNKNOWN"
 */
const char *mdns_class_to_string(uint16_t class);

/**
 * mdns_set_error() - set global error message
 * @fmt: printf-style format string
 * @...: format arguments
 *
 * Stores formatted error message in global context for retrieval by ucode.
 */
void mdns_set_error(const char *fmt, ...);

/* Callback slots within ctx.callbacks */
enum mdns_callback_slot {
	MDNS_CB_PACKET,
	MDNS_CB_INTERFACE_CHANGE,
	MDNS_CB_RATE_LIMIT,
	MDNS_CB_MAX
};

/**
 * mdns_callback_get() - read a registered callback
 * @slot: callback slot
 *
 * Return: the callback, or NULL if none is registered
 */
uc_value_t *mdns_callback_get(enum mdns_callback_slot slot);

/**
 * mdns_callback_set() - register a callback
 * @slot: callback slot
 * @fn: callback, or NULL to clear
 *
 * Return: true on success
 */
bool mdns_callback_set(enum mdns_callback_slot slot, uc_value_t *fn);

/**
 * mdns_callbacks_init() - create the callback holder
 * @vm: ucode VM
 */
void mdns_callbacks_init(uc_vm_t *vm);

/**
 * mdns_monotonic_ms() - milliseconds from a clock that never steps
 *
 * Return: milliseconds since an unspecified epoch
 */
int64_t mdns_monotonic_ms(void);

/**
 * mdns_info() - output info message to stdout
 * @fmt: printf-style format string
 * @...: format arguments
 *
 * Prints info message to stdout if cfg.debug enabled (ctx.debug).
 */
void mdns_info(const char *fmt, ...);

/**
 * mdns_debug() - output debug message to stdout
 * @fmt: printf-style format string
 * @...: format arguments
 *
 * Prints debug message to stdout if cfg.trace enabled (ctx.trace).
 */
void mdns_debug(const char *fmt, ...);

/**
 * mdns_set_trace() - set trace flag
 * @enabled: true to enable trace output, false to disable
 *
 * Sets ctx.trace flag to control mdns_debug() output.
 */
void mdns_set_trace(bool enabled);

/* callback.c - Ucode callback invocation */

/**
 * mdns_callback_packet() - invoke on_packet callback
 * @iface: interface packet received on
 * @pkt: parsed packet
 * @from: source address
 * @multicast: true if received on multicast socket
 * @is_legacy: true if source port != 5353 (legacy unicast query)
 *
 * Converts packet and metadata to ucode objects, invokes registered
 * on_packet callback function if set.
 */
void mdns_callback_packet(struct mdns_interface *iface, struct mdns_packet *pkt,
			   struct sockaddr_storage *from, bool multicast, bool is_legacy);

/**
 * mdns_callback_interface_change() - invoke on_interface_change callback
 * @iface: interface that changed
 * @event: event type (up/down/addr_add/addr_del)
 *
 * Notifies ucode layer of interface state changes.
 */
void mdns_callback_interface_change(struct mdns_interface *iface,
				    enum mdns_interface_event event);

/**
 * mdns_callback_rate_limit() - invoke on_rate_limit callback
 * @iface: interface for send operation
 * @packet_len: size of packet to send
 *
 * Queries ucode layer whether send should proceed based on rate limiting.
 *
 * Return: true if send allowed, false if rate limited
 */
bool mdns_callback_rate_limit(struct mdns_interface *iface, size_t packet_len);

/* queue.c - Packet queuing and rate limiting */

/**
 * packet_queue_init() - initialise packet queue subsystem
 *
 * Initialises queue structures and rate limiters.
 * Called during daemon startup.
 */
void packet_queue_init(void);

/**
 * packet_queue_cleanup() - shutdown packet queue subsystem
 *
 * Frees queued packets, cancels timers.
 * Called during daemon shutdown.
 */
void packet_queue_cleanup(void);

/**
 * packet_queue_flush() - send everything queued, ignoring the rate limiter
 *
 * For shutdown, where the queued packets are the goodbyes.
 */
void packet_queue_flush(void);

/**
 * packet_queue_purge() - drop queued packets for an interface
 * @iface: interface being destroyed
 *
 * Queued packets reference the interface's sockets; they must be
 * discarded before the interface is freed.
 */
void packet_queue_purge(struct mdns_interface *iface);

/**
 * packet_queue_send() - send packet with rate limiting
 * @sock: socket to send through
 * @data: packet data
 * @len: packet length
 * @dest: destination address (fully resolved, never NULL)
 * @dest_len: destination address length
 *
 * RFC 6762 Section 6: Implements token bucket rate limiting.
 * If rate limit allows, returns false (caller should send immediately).
 * If rate limited, queues packet and returns true (packet queued).
 * Starts 100ms timer to process queue when packets are queued.
 *
 * Return: true if queued, false if not rate limited
 */
bool packet_queue_send(struct mdns_socket *sock, const uint8_t *data, size_t len,
		       struct sockaddr *dest, socklen_t dest_len);

#endif /* __MDNS_H */
