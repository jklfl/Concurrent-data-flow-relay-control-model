#ifndef __PARSE_H__
#define __PARSE_H__
#include "interface.h"
struct localhost { 	int fd;
		uint32_t localip; 	uint8_t localmac[RTE_ETHER_ADDR_LEN];
	uint16_t localport;
	uint8_t protocol;
	struct rte_ring *sndbuf;
	struct rte_ring *rcvbuf;
	struct localhost *prev; 	struct localhost *next;
	pthread_cond_t cond;
	pthread_mutex_t mutex;
};
static struct localhost *lhost = NULL;
#define DEFAULT_FD_NUM	3
#define MAX_FD_COUNT	1024
static unsigned char fd_table[MAX_FD_COUNT] = {0};
static int get_fd_frombitmap(void) {
	int fd = DEFAULT_FD_NUM;
	for ( ;fd < MAX_FD_COUNT;fd ++) {
		if ((fd_table[fd/8] & (0x1 << (fd % 8))) == 0) {
			fd_table[fd/8] |= (0x1 << (fd % 8));
			return fd;
		}
	}
	return -1;
}
static int set_fd_frombitmap(int fd) {
	if (fd >= MAX_FD_COUNT) return -1;
	fd_table[fd/8] &= ~(0x1 << (fd % 8));
	return 0;
}
static struct ng_tcp_stream *get_accept_tcb(uint16_t dport) {
	struct ng_tcp_stream *apt;
	struct ng_tcp_table *table = tcpInstance();
	for (apt = table->tcb_set;apt != NULL;apt = apt->next) {
		if (dport == apt->dport && apt->fd == -1) {
			return apt;
		}
	}
	return NULL;
}
static void* get_hostinfo_fromfd(int sockfd) {
	struct localhost *host;
	for (host = lhost; host != NULL;host = host->next) {
		if (sockfd == host->fd) {
			return host;
		}
	}
#if ENABLE_TCP_APP
	struct ng_tcp_stream *stream = NULL;
	struct ng_tcp_table *table = tcpInstance();
	for (stream = table->tcb_set;stream != NULL;stream = stream->next) {
		if (sockfd == stream->fd) {
			return stream;
		}
	}
#endif
#if ENABLE_SINGLE_EPOLL
	struct eventpoll *ep = table->ep;
	if (ep != NULL) {
		if (ep->fd == sockfd) {
			return ep;
		}
	}
#endif
	return NULL;
}
static struct localhost * get_hostinfo_fromip_port(uint32_t dip, uint16_t port, uint8_t proto) {
	struct localhost *host;
	for (host = lhost; host != NULL;host = host->next) {
		if (dip == host->localip && port == host->localport && proto == host->protocol) {
			return host;
		}
	}
	return NULL;
}
struct offload { 	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport; 	int protocol;
	unsigned char *data;
	uint16_t length;
}; 
#define TCP_OPTION_LENGTH	10
#define TCP_MAX_SEQ		4294967295
#define TCP_INITIAL_WINDOW  14600
typedef enum _NG_TCP_STATUS {
	NG_TCP_STATUS_CLOSED = 0,
	NG_TCP_STATUS_LISTEN,
	NG_TCP_STATUS_SYN_RCVD,
	NG_TCP_STATUS_SYN_SENT,
	NG_TCP_STATUS_ESTABLISHED,
	NG_TCP_STATUS_FIN_WAIT_1,
	NG_TCP_STATUS_FIN_WAIT_2,
	NG_TCP_STATUS_CLOSING,
	NG_TCP_STATUS_TIME_WAIT,
	NG_TCP_STATUS_CLOSE_WAIT,
	NG_TCP_STATUS_LAST_ACK
} NG_TCP_STATUS;
struct ng_tcp_stream { 	int fd; 	uint32_t dip;
	uint8_t localmac[RTE_ETHER_ADDR_LEN];
	uint16_t dport;
	uint8_t protocol;
	uint16_t sport;
	uint32_t sip;
	uint32_t snd_nxt; 	uint32_t rcv_nxt; 	NG_TCP_STATUS status;
#if 0
	union {
		struct {
			struct ng_tcp_stream *syn_set; 			struct ng_tcp_stream *accept_set; 		};
		struct {
			struct rte_ring *sndbuf;
			struct rte_ring *rcvbuf;
		};
	};
#else
	struct rte_ring *sndbuf;
	struct rte_ring *rcvbuf;
#endif
	struct ng_tcp_stream *prev;
	struct ng_tcp_stream *next;
	pthread_cond_t cond;
	pthread_mutex_t mutex;
};
struct ng_tcp_fragment { 
	uint16_t sport;  
	uint16_t dport;  
	uint32_t seqnum;  
	uint32_t acknum;  
	uint8_t  hdrlen_off;  
	uint8_t  tcp_flags; 
	uint16_t windows;   
	uint16_t cksum;     
	uint16_t tcp_urp;  
	int optlen;
	uint32_t option[TCP_OPTION_LENGTH];
	unsigned char *data;
	uint32_t length;
};
struct ng_tcp_table *tInst = NULL;
static struct ng_tcp_table *tcpInstance(void) {
	if (tInst == NULL) {
		tInst = rte_malloc("ng_tcp_table", sizeof(struct ng_tcp_table), 0);
		memset(tInst, 0, sizeof(struct ng_tcp_table));
	}
	return tInst;
}
int udp_process(struct rte_mbuf *udpmbuf);
int ng_encode_udp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
	uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
	unsigned char *data, uint16_t total_len);
struct rte_mbuf * ng_udp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
uint8_t *data, uint16_t length);
int udp_out(struct rte_mempool *mbuf_pool);
int ng_tcp_process(struct rte_mbuf *tcpmbuf);
int ng_encode_tcp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment);
struct rte_mbuf * ng_tcp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment);
int ng_tcp_out(struct rte_mempool *mbuf_pool);