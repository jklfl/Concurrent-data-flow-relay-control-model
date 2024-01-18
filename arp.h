#ifndef __ARP_H__
#define __ARP_H__
#include "Interface.h"
#define ARP_ENTRY_STATUS_DYNAMIC	0
#define ARP_ENTRY_STATUS_STATIC		1
#define TIMER_RESOLUTION_CYCLES 120000000000ULL 
struct rte_ring *ring_arp;
//uint32_t gLocalIp = MAKE_IPV4_ADDR(192, 168, 31, 110);
uint32_t gLocalIp;
uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
//uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN];
#define LL_ADD(item, list) do {		\
	item->prev = NULL;				\
	item->next = list;				\
	if (list != NULL) list->prev = item; \
	list = item;					\
} while(0)
#define LL_REMOVE(item, list) do {		\
	if (item->prev != NULL) item->prev->next = item->next;	\
	if (item->next != NULL) item->next->prev = item->prev;	\
	if (list == item) list = item->next;	\
	item->prev = item->next = NULL;			\
} while(0)

struct arp_entry {
	uint32_t ip;
	uint8_t hwaddr[RTE_ETHER_ADDR_LEN];
	uint8_t type; 
	struct arp_entry *next;
	struct arp_entry *prev;
};

struct arp_table {
	struct arp_entry *entries;
	int count;
			pthread_spinlock_t spinlock;
};


struct  arp_table *arpt;

struct  arp_table *arp_table_instance(void);

uint8_t* ng_get_dst_macaddr(uint32_t dip);

int ng_arp_entry_insert(uint32_t ip, uint8_t *mac);

int ng_encode_arp_pkt(uint8_t *msg, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip);

struct rte_mbuf *ng_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip);
#endif