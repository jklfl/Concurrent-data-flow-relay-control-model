#include "arp.h"

struct  arp_table *arp_table_instance(void) {
	if (arpt == NULL) {
		ring_arp = rte_ring_create("ring_arp", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		arpt =(struct arp_table *)rte_malloc("arp table", sizeof(struct  arp_table), 0);
		if (arpt == NULL) {
			rte_exit(EXIT_FAILURE, "rte_malloc arp table failed\n");
		}
		memset(arpt, 0, sizeof(struct arp_table));
                		pthread_spin_init(&arpt->spinlock, PTHREAD_PROCESS_SHARED);
	}
	return arpt;
}


uint8_t* ng_get_dst_macaddr(uint32_t dip) {
	struct arp_entry *iter;
	struct arp_table *table = arp_table_instance();
	int count = table->count;
	for (iter = table->entries; count-- != 0 && iter != NULL;iter = iter->next) {
		if (dip == iter->ip) {
			return iter->hwaddr;
		}
	}
	return NULL;
}

int ng_arp_entry_insert(uint32_t ip, uint8_t *mac) {
	struct arp_table *table = arp_table_instance();
	uint8_t *hwaddr = ng_get_dst_macaddr(ip);
	if (hwaddr == NULL) {
		struct arp_entry *entry = rte_malloc("arp_entry",sizeof(struct arp_entry), 0);
		if (entry) {
			memset(entry, 0, sizeof(struct arp_entry));
			entry->ip = ip;
			rte_memcpy(entry->hwaddr, mac, RTE_ETHER_ADDR_LEN);
			entry->type = 0;
			pthread_spin_lock(&table->spinlock);
			LL_ADD(entry, table->entries);
			table->count ++;
			pthread_spin_unlock(&table->spinlock);
		}
		return 1; 	}
	return 0;
}


int ng_encode_arp_pkt(uint8_t *msg, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
		struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	if (!strncmp((const char *)dst_mac, (const char *)gDefaultArpMac, RTE_ETHER_ADDR_LEN)) {
		uint8_t mac[RTE_ETHER_ADDR_LEN] = {0x0};
		rte_memcpy(eth->d_addr.addr_bytes, mac, RTE_ETHER_ADDR_LEN);
	} else {
		rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	}
	eth->ether_type = htons(RTE_ETHER_TYPE_ARP);
		struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
	arp->arp_hardware = htons(1);
	arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	arp->arp_hlen = RTE_ETHER_ADDR_LEN;
	arp->arp_plen = sizeof(uint32_t);
	arp->arp_opcode = htons(opcode);
	rte_memcpy(arp->arp_data.arp_sha.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	arp->arp_data.arp_sip = sip;
	arp->arp_data.arp_tip = dip;
	return 0;
}

struct rte_mbuf *ng_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "ng_send_arp rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;
	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
	ng_encode_arp_pkt(pkt_data, opcode, dst_mac, sip, dip);
	return mbuf;
}