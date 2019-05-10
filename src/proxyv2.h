/*-
 * Written by Dridi Boukelmoune <dridi.boukelmoune@gmail.com>
 *
 * This file is in the public domain.
 *
 * PROXY protocol v2 definitions, last updated 2017/03/10.
 */

/* PROXY v2 header */

#define PP2_HEADER_MAX		536

union pp2_addr {
	struct {		/* for TCP/UDP over IPv4, len = 12 */
		uint32_t	src_addr;
		uint32_t	dst_addr;
		uint16_t	src_port;
		uint16_t	dst_port;
	} ipv4;
	struct {		/* for TCP/UDP over IPv6, len = 36 */
		uint8_t 	src_addr[16];
		uint8_t 	dst_addr[16];
		uint16_t	src_port;
		uint16_t	dst_port;
	} ipv6;
	struct {		/* for AF_UNIX sockets, len = 216 */
		uint8_t		rc_addr[108];
		uint8_t		st_addr[108];
	} local;
};

struct pp2_hdr {
	uint8_t		sig[12];
	uint8_t		ver_cmd;
	uint8_t		fam;
	uint16_t	len;	/* number of following bytes of the header */
	union pp2_addr	addr;
};

const uint8_t PP2_SIG[12] = {
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D,
    0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
};

/* First octet past the magic marker, command and version */

#define PP2_CMD_LOCAL		0x00
#define PP2_CMD_PROXY		0x01
#define PP2_CMD_MASK		0x0F

#define PP2_VERSION		0x20
#define PP2_VERSION_MASK	0xF0

/* Second octet, transport protocol and address family */

#define PP2_TRANS_UNSPEC	0x00
#define PP2_TRANS_STREAM	0x01
#define PP2_TRANS_DGRAM		0x02
#define PP2_TRANS_MASK		0x0F

#define PP2_FAM_UNSPEC		0x00
#define PP2_FAM_INET		0x10
#define PP2_FAM_INET6		0x20
#define PP2_FAM_UNIX		0x30
#define PP2_FAM_MASK		0xF0

/* Type-Length-Value (TLV) fields */

struct pp2_tlv {
	uint8_t	type;
	uint8_t	length_hi;
	uint8_t	length_lo;
	uint8_t	value[0];
};

#define PP2_TYPE_ALPN		0x01
#define PP2_TYPE_AUTHORITY	0x02
#define PP2_TYPE_CRC32C		0x03
#define PP2_TYPE_NOOP		0x04
#define PP2_TYPE_SSL		0x20
#define PP2_SUBTYPE_SSL_VERSION 0x21
#define PP2_SUBTYPE_SSL_CN	0x22
#define PP2_SUBTYPE_SSL_CIPHER	0x23
#define PP2_SUBTYPE_SSL_SIG_ALG	0x24
#define PP2_SUBTYPE_SSL_KEY_ALG	0x25
#define PP2_TYPE_NETNS		0x30

#define PP2_TYPE_MIN_CUSTOM	0xE0
#define PP2_TYPE_MAX_CUSTOM	0xEF

#define PP2_TYPE_MIN_EXPERIMENT	0xF0
#define PP2_TYPE_MAX_EXPERIMENT	0xF7

#define PP2_TYPE_MIN_FUTURE	0xF8
#define PP2_TYPE_MAX_FUTURE	0xFF

struct pp2_tlv_ssl {
	uint8_t		client;
	uint32_t	verify;
	struct pp2_tlv	sub_tlv[0];
};

#define PP2_CLIENT_SSL		0x01
#define PP2_CLIENT_CERT_CONN	0x02
#define PP2_CLIENT_CERT_SESS	0x04
