#ifndef __INCLUDE_PARSER_H__
#define __INCLUDE_PARSER_H__
#include <stdint.h>
#include <rte_ip.h>
#include <rte_ether.h>
#define PARSE_DELIMITER				" \f\n\r\t\v"
#define skip_white_spaces(pos)			\
({						\
	__typeof__(pos) _p = (pos);		\
	for ( ; isspace(*_p); _p++)		\
		;				\
	_p;					\
})
static inline size_t
skip_digits(const char *src)
{
	size_t i;
	for (i = 0; isdigit(src[i]); i++)
		;
	return i;
}
int parser_read_arg_bool(const char *p);
int parser_read_int32(int32_t *value, const char *p);
int parser_read_uint64(uint64_t *value, const char *p);
int parser_read_uint32(uint32_t *value, const char *p);
int parser_read_uint16(uint16_t *value, const char *p);
int parser_read_uint8(uint8_t *value, const char *p);
int parser_read_uint64_hex(uint64_t *value, const char *p);
int parser_read_uint32_hex(uint32_t *value, const char *p);
int parser_read_uint16_hex(uint16_t *value, const char *p);
int parser_read_uint8_hex(uint8_t *value, const char *p);
int parse_hex_string(char *src, uint8_t *dst, uint32_t *size);
int parse_ipv4_addr(const char *token, struct in_addr *ipv4);
int parse_ipv6_addr(const char *token, struct in6_addr *ipv6);
int parse_mac_addr(const char *token, struct ether_addr *addr);
int parse_mpls_labels(char *string, uint32_t *labels, uint32_t *n_labels);
int parse_l4_proto(const char *token, uint8_t *proto);
int parse_tokenize_string(char *string, char *tokens[], uint32_t *n_tokens);
int parse_pipeline_core(uint32_t *socket, uint32_t *core, uint32_t *ht,	const char *entry);
int str_split(char *str, const char *delim, char *tokens[], int limit);
int parse_ipv4_port(const char *token, uint32_t *ip, uint16_t *port);
static inline void
mac_addr_tostring(struct ether_addr *addr, char *buf, size_t len)
{
	snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
			addr->addr_bytes[0],
			addr->addr_bytes[1],
			addr->addr_bytes[2],
			addr->addr_bytes[3],
			addr->addr_bytes[4],
			addr->addr_bytes[5]);
}
static inline void
ipv4_addr_tostring(uint32_t ipv4, char *buf, size_t len)
{
	ipv4 = rte_be_to_cpu_32(ipv4);
	snprintf(buf, len, "%u.%u.%u.%u",
			(unsigned char)(ipv4 >> 24 & 0xff),
			(unsigned char)(ipv4 >> 16 & 0xff),
			(unsigned char)(ipv4 >> 8 & 0xff),
			(unsigned char)(ipv4 & 0xff));
}
#endif
