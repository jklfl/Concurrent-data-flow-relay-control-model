#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <getopt.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <malloc.h>
#include <rte_errno.h>
#include <rte_cfgfile.h>
#include <rte_string_fns.h>
#include "utils.h"
static uint32_t
get_hex_val(char c)
{
	switch (c) {
	case '0': case '1': case '2': case '3': case '4': case '5':
	case '6': case '7': case '8': case '9':
		return c - '0';
	case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
		return c - 'A' + 10;
	case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
		return c - 'a' + 10;
	default:
		return 0;
	}
}
int
parser_read_arg_bool(const char *p)
{
	p = skip_white_spaces(p);
	int result = -EINVAL;
	if (((p[0] == 'y') && (p[1] == 'e') && (p[2] == 's')) ||
		((p[0] == 'Y') && (p[1] == 'E') && (p[2] == 'S'))) {
		p += 3;
		result = 1;
	}
	if (((p[0] == 'o') && (p[1] == 'n')) ||
		((p[0] == 'O') && (p[1] == 'N'))) {
		p += 2;
		result = 1;
	}
	if (((p[0] == 'n') && (p[1] == 'o')) ||
		((p[0] == 'N') && (p[1] == 'O'))) {
		p += 2;
		result = 0;
	}
	if (((p[0] == 'o') && (p[1] == 'f') && (p[2] == 'f')) ||
		((p[0] == 'O') && (p[1] == 'F') && (p[2] == 'F'))) {
		p += 3;
		result = 0;
	}
	p = skip_white_spaces(p);
	if (p[0] != '\0')
		return -EINVAL;
	return result;
}
int
parser_read_uint64(uint64_t *value, const char *p)
{
	char *next;
	uint64_t val;
	p = skip_white_spaces(p);
	if (!isdigit(*p))
		return -EINVAL;
	val = strtoul(p, &next, 10);
	if (p == next)
		return -EINVAL;
	p = next;
	switch (*p) {
	case 'T':
		val *= 1024ULL;
	case 'G':
		val *= 1024ULL;
	case 'M':
		val *= 1024ULL;
	case 'k':
	case 'K':
		val *= 1024ULL;
		p++;
		break;
	}
	p = skip_white_spaces(p);
	if (*p != '\0')
		return -EINVAL;
	*value = val;
	return 0;
}
int
parser_read_uint64_hex(uint64_t *value, const char *p)
{
	char *next;
	uint64_t val;
	p = skip_white_spaces(p);
	val = strtoul(p, &next, 16);
	if (p == next)
		return -EINVAL;
	p = skip_white_spaces(next);
	if (*p != '\0')
		return -EINVAL;
	*value = val;
	return 0;
}
int
parser_read_int32(int32_t *value, const char *p)
{
	char *next;
	int32_t val;
	p = skip_white_spaces(p);
	if (!isdigit(*p))
		return -EINVAL;
	val = strtol(p, &next, 10);
	if (p == next)
		return -EINVAL;
	*value = val;
	return 0;
}
int
parser_read_uint32(uint32_t *value, const char *p)
{
	uint64_t val = 0;
	int ret = parser_read_uint64(&val, p);
	if (ret < 0)
		return ret;
	if (val > UINT32_MAX)
		return -ERANGE;
	*value = val;
	return 0;
}
int
parser_read_uint32_hex(uint32_t *value, const char *p)
{
	uint64_t val = 0;
	int ret = parser_read_uint64_hex(&val, p);
	if (ret < 0)
		return ret;
	if (val > UINT32_MAX)
		return -ERANGE;
	*value = val;
	return 0;
}
int
parser_read_uint16(uint16_t *value, const char *p)
{
	uint64_t val = 0;
	int ret = parser_read_uint64(&val, p);
	if (ret < 0)
		return ret;
	if (val > UINT16_MAX)
		return -ERANGE;
	*value = val;
	return 0;
}
int
parser_read_uint16_hex(uint16_t *value, const char *p)
{
	uint64_t val = 0;
	int ret = parser_read_uint64_hex(&val, p);
	if (ret < 0)
		return ret;
	if (val > UINT16_MAX)
		return -ERANGE;
	*value = val;
	return 0;
}
int
parser_read_uint8(uint8_t *value, const char *p)
{
	uint64_t val = 0;
	int ret = parser_read_uint64(&val, p);
	if (ret < 0)
		return ret;
	if (val > UINT8_MAX)
		return -ERANGE;
	*value = val;
	return 0;
}
int
parser_read_uint8_hex(uint8_t *value, const char *p)
{
	uint64_t val = 0;
	int ret = parser_read_uint64_hex(&val, p);
	if (ret < 0)
		return ret;
	if (val > UINT8_MAX)
		return -ERANGE;
	*value = val;
	return 0;
}
int
parse_tokenize_string(char *string, char *tokens[], uint32_t *n_tokens)
{
	uint32_t i;
	if ((string == NULL) ||
		(tokens == NULL) ||
		(*n_tokens < 1))
		return -EINVAL;
	for (i = 0; i < *n_tokens; i++) {
		tokens[i] = strtok_r(string, PARSE_DELIMITER, &string);
		if (tokens[i] == NULL)
			break;
	}
	if ((i == *n_tokens) &&
		(NULL != strtok_r(string, PARSE_DELIMITER, &string)))
		return -E2BIG;
	*n_tokens = i;
	return 0;
}
int
parse_hex_string(char *src, uint8_t *dst, uint32_t *size)
{
	char *c;
	uint32_t len, i;
	if ((src == NULL) ||
		(dst == NULL) ||
		(size == NULL) ||
		(*size == 0))
		return -1;
	len = strlen(src);
	if (((len & 3) != 0) ||
		(len > (*size) * 2))
		return -1;
	*size = len / 2;
	for (c = src; *c != 0; c++) {
		if ((((*c) >= '0') && ((*c) <= '9')) ||
			(((*c) >= 'A') && ((*c) <= 'F')) ||
			(((*c) >= 'a') && ((*c) <= 'f')))
			continue;
		return -1;
	}
	for (i = 0; i < *size; i++)
		dst[i] = get_hex_val(src[2 * i]) * 16 +
			get_hex_val(src[2 * i + 1]);
	return 0;
}
int
parse_mpls_labels(char *string, uint32_t *labels, uint32_t *n_labels)
{
	uint32_t n_max_labels = *n_labels, count = 0;
	if (strcmp(string, "<void>") == 0) {
		*n_labels = 0;
		return 0;
	}
	for ( ; (*string != '\0'); ) {
		char *next;
		int value;
		if (count >= n_max_labels)
			return -1;
		if (count > 0) {
			if (string[0] != ':')
				return -1;
			string++;
		}
		value = strtol(string, &next, 10);
		if (next == string)
			return -1;
		string = next;
		labels[count++] = (uint32_t) value;
	}
	*n_labels = count;
	return 0;
}
#define INADDRSZ 4
#define IN6ADDRSZ 16
static int
inet_pton4(const char *src, unsigned char *dst)
{
	static const char digits[] = "0123456789";
	int saw_digit, octets, ch;
	unsigned char tmp[INADDRSZ], *tp;
	saw_digit = 0;
	octets = 0;
	*(tp = tmp) = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;
		pch = strchr(digits, ch);
		if (pch != NULL) {
			unsigned int new = *tp * 10 + (pch - digits);
			if (new > 255)
				return 0;
			if (!saw_digit) {
				if (++octets > 4)
					return 0;
				saw_digit = 1;
			}
			*tp = (unsigned char)new;
		} else if (ch == '.' && saw_digit) {
			if (octets == 4)
				return 0;
			*++tp = 0;
			saw_digit = 0;
		} else
			return 0;
	}
	if (octets < 4)
		return 0;
	memcpy(dst, tmp, INADDRSZ);
	return 1;
}
static int
inet_pton6(const char *src, unsigned char *dst)
{
	static const char xdigits_l[] = "0123456789abcdef",
		xdigits_u[] = "0123456789ABCDEF";
	unsigned char tmp[IN6ADDRSZ], *tp = 0, *endp = 0, *colonp = 0;
	const char *xdigits = 0, *curtok = 0;
	int ch = 0, saw_xdigit = 0, count_xdigit = 0;
	unsigned int val = 0;
	unsigned dbloct_count = 0;
	memset((tp = tmp), '\0', IN6ADDRSZ);
	endp = tp + IN6ADDRSZ;
	colonp = NULL;
	if (*src == ':')
		if (*++src != ':')
			return 0;
	curtok = src;
	saw_xdigit = count_xdigit = 0;
	val = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;
		pch = strchr((xdigits = xdigits_l), ch);
		if (pch == NULL)
			pch = strchr((xdigits = xdigits_u), ch);
		if (pch != NULL) {
			if (count_xdigit >= 4)
				return 0;
			val <<= 4;
			val |= (pch - xdigits);
			if (val > 0xffff)
				return 0;
			saw_xdigit = 1;
			count_xdigit++;
			continue;
		}
		if (ch == ':') {
			curtok = src;
			if (!saw_xdigit) {
				if (colonp)
					return 0;
				colonp = tp;
				continue;
			} else if (*src == '\0') {
				return 0;
			}
			if (tp + sizeof(int16_t) > endp)
				return 0;
			*tp++ = (unsigned char) ((val >> 8) & 0xff);
			*tp++ = (unsigned char) (val & 0xff);
			saw_xdigit = 0;
			count_xdigit = 0;
			val = 0;
			dbloct_count++;
			continue;
		}
		if (ch == '.' && ((tp + INADDRSZ) <= endp) &&
		    inet_pton4(curtok, tp) > 0) {
			tp += INADDRSZ;
			saw_xdigit = 0;
			dbloct_count += 2;
			break;  
		}
		return 0;
	}
	if (saw_xdigit) {
		if (tp + sizeof(int16_t) > endp)
			return 0;
		*tp++ = (unsigned char) ((val >> 8) & 0xff);
		*tp++ = (unsigned char) (val & 0xff);
		dbloct_count++;
	}
	if (colonp != NULL) {
		if (dbloct_count == 8)
			return 0;
		const int n = tp - colonp;
		int i;
		for (i = 1; i <= n; i++) {
			endp[-i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	if (tp != endp)
		return 0;
	memcpy(dst, tmp, IN6ADDRSZ);
	return 1;
}
static struct ether_addr *
my_ether_aton(const char *a)
{
	int i;
	char *end;
	unsigned long o[ETHER_ADDR_LEN];
	static struct ether_addr ether_addr;
	i = 0;
	do {
		errno = 0;
		o[i] = strtoul(a, &end, 16);
		if (errno != 0 || end == a || (end[0] != ':' && end[0] != 0))
			return NULL;
		a = end + 1;
	} while (++i != sizeof(o) / sizeof(o[0]) && end[0] != 0);
	if (end[0] != 0)
		return NULL;
	if (i == ETHER_ADDR_LEN) {
		while (i-- != 0) {
			if (o[i] > UINT8_MAX)
				return NULL;
			ether_addr.addr_bytes[i] = (uint8_t)o[i];
		}
	} else if (i == ETHER_ADDR_LEN / 2) {
		while (i-- != 0) {
			if (o[i] > UINT16_MAX)
				return NULL;
			ether_addr.addr_bytes[i * 2] = (uint8_t)(o[i] >> 8);
			ether_addr.addr_bytes[i * 2 + 1] = (uint8_t)(o[i] & 0xff);
		}
	} else
		return NULL;
	return (struct ether_addr *)&ether_addr;
}
int
parse_ipv4_addr(const char *token, struct in_addr *ipv4)
{
	if (strlen(token) >= INET_ADDRSTRLEN)
		return -EINVAL;
	if (inet_pton4(token, (unsigned char *)ipv4) != 1)
		return -EINVAL;
	return 0;
}
int
parse_ipv6_addr(const char *token, struct in6_addr *ipv6)
{
	if (strlen(token) >= INET6_ADDRSTRLEN)
		return -EINVAL;
	if (inet_pton6(token, (unsigned char *)ipv6) != 1)
		return -EINVAL;
	return 0;
}
int
parse_mac_addr(const char *token, struct ether_addr *addr)
{
	struct ether_addr *tmp;
	tmp = my_ether_aton(token);
	if (tmp == NULL)
		return -1;
	memcpy(addr, tmp, sizeof(struct ether_addr));
	return 0;
}
int
parse_l4_proto(const char *token, uint8_t *proto)
{
	if (strcasecmp(token, "tcp") == 0) {
		*proto = IPPROTO_TCP;
		return 0;
	}
	if (strcasecmp(token, "udp") == 0) {
		*proto = IPPROTO_UDP;
		return 0;
	}
	return -1;
}
int
parse_pipeline_core(uint32_t *socket,
	uint32_t *core,
	uint32_t *ht,
	const char *entry)
{
	size_t num_len;
	char num[8];
	uint32_t s = 0, c = 0, h = 0, val;
	uint8_t s_parsed = 0, c_parsed = 0, h_parsed = 0;
	const char *next = skip_white_spaces(entry);
	char type;
	while (*next != '\0') {
		if (s_parsed && c_parsed && h_parsed)
			return -EINVAL;
		type = *next;
		switch (type) {
		case 's':
		case 'S':
			if (s_parsed || c_parsed || h_parsed)
				return -EINVAL;
			s_parsed = 1;
			next++;
			break;
		case 'c':
		case 'C':
			if (c_parsed || h_parsed)
				return -EINVAL;
			c_parsed = 1;
			next++;
			break;
		case 'h':
		case 'H':
			if (h_parsed)
				return -EINVAL;
			h_parsed = 1;
			next++;
			break;
		default:
			if (!isdigit(*next) || s_parsed || c_parsed || h_parsed)
				return -EINVAL;
			type = 'C';
		}
		for (num_len = 0; *next != '\0'; next++, num_len++) {
			if (num_len == RTE_DIM(num))
				return -EINVAL;
			if (!isdigit(*next))
				break;
			num[num_len] = *next;
		}
		if (num_len == 0 && type != 'h' && type != 'H')
			return -EINVAL;
		if (num_len != 0 && (type == 'h' || type == 'H'))
			return -EINVAL;
		num[num_len] = '\0';
		val = strtol(num, NULL, 10);
		h = 0;
		switch (type) {
		case 's':
		case 'S':
			s = val;
			break;
		case 'c':
		case 'C':
			c = val;
			break;
		case 'h':
		case 'H':
			h = 1;
			break;
		}
	}
	*socket = s;
	*core = c;
	*ht = h;
	return 0;
}
int
str_split(char *str, const char *delim, char *tokens[], int limit)
{
	char *p;
	int count = 0;
	p = strtok(str, delim);
	while (p != NULL && count < limit) {
		tokens[count++] = p;
		p = strtok(NULL, delim);
	}
	return count;
}
int
parse_ipv4_port(const char *token, uint32_t *ip, uint16_t *port)
{
	char *t, *p;
	t = strdup(token);
	if (t == NULL)
		return -1;
	p = strtok(t, ":");
	if (!p || parse_ipv4_addr(p, (struct in_addr *)ip) < 0) {
		free(t);
		return -1;
	}
	p = strtok(NULL, ":");
	if (!p || parser_read_uint16(port, p) < 0) {
		free(t);
		return -1;
	}
	*port = htons(*port);
	free(t);
	return 0;
}
