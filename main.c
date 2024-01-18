#include "Interface.h"
#include "arp.h"
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "model_predictive_control/MPC.hpp"
#define N_MAX 1000 
#define NUM_MBUFS (4096-1)
#define RTE_TX_DESC_DEFAULT 1024
#define RTE_RX_DESC_DEFAULT 1024
#define BURST_SIZE	32
#define PRINT_MAC(addr)     printf("%02"PRIx8":%02"PRIx8":%02"PRIx8 \
        ":%02"PRIx8":%02"PRIx8":%02"PRIx8,  \
        addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2], \
        addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5])
#define ENABLE_KNI_APP      1
#define ENABLE_ARP_APP      1
#define ENABLE_ICMP_APP     1
#define ENABLE_TIMER		1
#define ENABLE_DETECT       1


static const struct rte_eth_conf port_conf = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};
//遍历并初始化所有绑定上DPDK的网卡
static void
slave_port_init(uint16_t portid, struct rte_mempool *mbuf_pool)
{
    int retval;
    uint16_t nb_rxd = RTE_RX_DESC_DEFAULT;
    uint16_t nb_txd = RTE_TX_DESC_DEFAULT;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;
    struct rte_eth_conf local_port_conf = port_conf;
        if (!rte_eth_dev_is_valid_port(portid))
        rte_exit(EXIT_FAILURE, "Invalid port\n");
        rte_eth_dev_info_get(portid, &dev_info);
    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
        local_port_conf.txmode.offloads |=
            DEV_TX_OFFLOAD_MBUF_FAST_FREE;
    local_port_conf.rx_adv_conf.rss_conf.rss_hf &=
        dev_info.flow_type_rss_offloads;
    if (local_port_conf.rx_adv_conf.rss_conf.rss_hf !=
            port_conf.rx_adv_conf.rss_conf.rss_hf) {
        printf("Port %u modified RSS hash function based on hardware support,"
            "requested:%#"PRIx64" configured:%#"PRIx64"\n",
            portid,
            port_conf.rx_adv_conf.rss_conf.rss_hf,
            local_port_conf.rx_adv_conf.rss_conf.rss_hf);
    }
        retval = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
    if (retval != 0)
        rte_exit(EXIT_FAILURE, "port %u: configuration failed (res=%d)\n",
                portid, retval);
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
    if (retval != 0)
        rte_exit(EXIT_FAILURE, "port %u: rte_eth_dev_adjust_nb_rx_tx_desc "
                "failed (res=%d)\n", portid, retval);
        rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = local_port_conf.rxmode.offloads;
    retval = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
                    rte_eth_dev_socket_id(portid),
                    &rxq_conf,
                    mbuf_pool);
    if (retval < 0)
        rte_exit(retval, " port %u: RX queue 0 setup failed (res=%d)",
                portid, retval);
        txq_conf = dev_info.default_txconf;
    txq_conf.offloads = local_port_conf.txmode.offloads;
    retval = rte_eth_tx_queue_setup(portid, 0, nb_txd,
                rte_eth_dev_socket_id(portid), &txq_conf);
    if (retval < 0)
        rte_exit(retval, "port %u: TX queue 0 setup failed (res=%d)",
                portid, retval);
        retval  = rte_eth_dev_start(portid);
    if (retval < 0)
        rte_exit(retval,
                "Start port %d failed (res=%d)",
                portid, retval);
    struct rte_ether_addr addr;
    rte_eth_macaddr_get(portid, &addr);
    printf("Port %u MAC: ", portid);
    PRINT_MAC(addr);
    printf("\n");
}
//网卡聚合
static void
bond_port_init(struct rte_mempool *mbuf_pool)
{
    int retval;
    uint8_t i;
    uint16_t nb_rxd = RTE_RX_DESC_DEFAULT;
    uint16_t nb_txd = RTE_TX_DESC_DEFAULT;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;
    struct rte_eth_conf local_port_conf = port_conf;
    uint16_t wait_counter = 20;
        retval = rte_eth_bond_create("net_bonding0", BONDING_MODE_ALB,
            0 );
    if (retval < 0)
        rte_exit(EXIT_FAILURE,
                "Faled to create bond port\n");
    BOND_PORT = retval;
    rte_eth_dev_info_get(BOND_PORT, &dev_info);
    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
        local_port_conf.txmode.offloads |=
            DEV_TX_OFFLOAD_MBUF_FAST_FREE;
    retval = rte_eth_dev_configure(BOND_PORT, 1, 1, &local_port_conf);
    if (retval != 0)
        rte_exit(EXIT_FAILURE, "port %u: configuration failed (res=%d)\n",
                BOND_PORT, retval);
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(BOND_PORT, &nb_rxd, &nb_txd);
    if (retval != 0)
        rte_exit(EXIT_FAILURE, "port %u: rte_eth_dev_adjust_nb_rx_tx_desc "
                "failed (res=%d)\n", BOND_PORT, retval);
        for (i = 0; i < slaves_count; i++) {
                if (rte_eth_bond_slave_add(BOND_PORT, slaves[i]) == -1)
            rte_exit(-1, "Oooops! adding slave (%u) to bond (%u) failed!\n",
                    slaves[i], BOND_PORT);
    }
    rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = local_port_conf.rxmode.offloads;
    retval = rte_eth_rx_queue_setup(BOND_PORT, 0, nb_rxd,
                    rte_eth_dev_socket_id(BOND_PORT),
                    &rxq_conf, mbuf_pool);
    if (retval < 0)
        rte_exit(retval, " port %u: RX queue 0 setup failed (res=%d)",
                BOND_PORT, retval);
    txq_conf = dev_info.default_txconf;
    txq_conf.offloads = local_port_conf.txmode.offloads;
    retval = rte_eth_tx_queue_setup(BOND_PORT, 0, nb_txd,
                rte_eth_dev_socket_id(BOND_PORT), &txq_conf);
    if (retval < 0)
        rte_exit(retval, "port %u: TX queue 0 setup failed (res=%d)",
                BOND_PORT, retval);
    retval  = rte_eth_dev_start(BOND_PORT);
    if (retval < 0)
        rte_exit(retval, "Start port %d failed (res=%d)", BOND_PORT, retval);
        while (wait_counter) {
        uint16_t act_slaves[16] = {0};
        if (rte_eth_bond_active_slaves_get(BOND_PORT, act_slaves, 16) ==
                slaves_count) {
            printf("\n");
            break;
        }
        sleep(1);
        printf("...");
        if (--wait_counter == 0)
            rte_exit(-1, "\nFailed to activate slaves\n");
    }
    rte_eth_promiscuous_enable(BOND_PORT);
    struct rte_ether_addr addr;
    rte_eth_macaddr_get(BOND_PORT, &addr);
    printf("Port %u MAC: ", (unsigned)BOND_PORT);
        PRINT_MAC(addr);
        printf("\n");
}
#if 0 
static uint16_t ng_checksum(uint16_t *addr, int count) {
	register long sum = 0;
	while (count > 1) {
		sum += *(unsigned short*)addr++;
		count -= 2;
	}
	if (count > 0) {
		sum += *(unsigned char *)addr;
	}
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	return ~sum;
}

static int ng_encode_icmp_pkt(uint8_t *msg, uint8_t *dst_mac,
		uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) {
		struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
		struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; 	ip->next_proto_id = IPPROTO_ICMP;
	ip->src_addr = sip;
	ip->dst_addr = dip;
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);
		struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
	icmp->icmp_code = 0;
	icmp->icmp_ident = id;
	icmp->icmp_seq_nb = seqnb;
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = ng_checksum((uint16_t*)icmp, sizeof(struct rte_icmp_hdr));
	return 0;
}


static struct rte_mbuf *ng_send_icmp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac,
		uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) {
	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr);
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;
	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
	ng_encode_icmp_pkt(pkt_data, dst_mac, sip, dip, id, seqnb);
	return mbuf;
}
#endif






static int send_pkt(){
    struct rte_mbuf *tx[BURST_SIZE];
    unsigned nb_tx = rte_ring_mc_dequeue_burst(r1, (void**)tx, BURST_SIZE, NULL);
    if (nb_tx > 0) {
        		parse_mbuf(tx);
		rte_eth_tx_burst(BOND_PORT, 0, tx, nb_tx);
    }
	nb_tx = rte_ring_mc_dequeue_burst(r2, (void**)tx, BURST_SIZE, NULL);
    if (nb_tx > 0) {
				parse_mbuf(tx);
        rte_eth_tx_burst(BOND_PORT, 0, tx, nb_tx);
    }
	nb_tx = rte_ring_mc_dequeue_burst(r3, (void**)tx, BURST_SIZE, NULL);
    if (nb_tx > 0) {
		        parse_mbuf(tx);
		rte_eth_tx_burst(BOND_PORT, 0, tx, nb_tx);
    }
#if ENABLE_ARP_APP
        nb_tx = rte_ring_mc_dequeue_burst(ring_arp,(void **)tx,BURST_SIZE,NULL);
    if(nb_tx > 0){
        rte_eth_tx_burst(BOND_PORT, 0, tx,nb_tx);
    }
#endif
	unsigned i = 0;
	for (i = 0;i < BURST_SIZE;i ++) {
            if(tx[i] != NULL)
				rte_pktmbuf_free(tx[i]);
        }
	return 0;
}
#if ENABLE_DETECT
#define CAPTURE_WINDOWS		256

static double tresh = 1200.0;

static uint32_t p_setbits[CAPTURE_WINDOWS] = {0};
static uint32_t p_totbits[CAPTURE_WINDOWS] = {0};
static double p_entropy[CAPTURE_WINDOWS] = {0};
static int pkt_idx = 0;


static double ddos_entropy(double set_bits, double total_bits) {
	return ( - set_bits) * (log2(set_bits) - log2(total_bits)) 	- (total_bits - set_bits) * (log2(total_bits - set_bits) - log2(total_bits))
	+ log2(total_bits);
}


static uint32_t count_bit(uint8_t *msg, const uint32_t length) {
#if 0
	uint32_t v; 	uint32_t c, set_bits = 0; 	static const int S[5] = {1, 2, 4, 8, 16}; 	static const int B[5] = {0x55555555, 0x33333333, 0x0F0F0F0F, 0x00FF00FF, 0x0000FFFF};
	uint32_t *ptr = (uint32_t *)msg;
	uint32_t *end = (uint32_t *)msg + length;
	while (ptr < end) {
		v = *ptr++;
		c = v - ((v >> S[0]) & B[0]);
		c = ((c >> S[1]) & B[1]) + (c & B[1]);
		c = ((c >> S[2]) + c) & B[2];
		c = ((c >> S[3]) + c) & B[3];
		c = ((c >> S[4]) + c) & B[4];
		set_bits += c;
	}
#else
	uint64_t v, set_bits = 0;
   	const uint64_t *ptr = (uint64_t *) msg;
   	const uint64_t *end = (uint64_t *) (msg + length);
	do {
      v = *(ptr++);
      v = v - ((v >> 1) & 0x5555555555555555);                          v = (v & 0x3333333333333333) + ((v >> 2) & 0x3333333333333333);           v = (v + (v >> 4)) & 0x0F0F0F0F0F0F0F0F;
      set_bits += (v * 0x0101010101010101) >> (sizeof(v) - 1) * 8; 
    } while(end > ptr);
#endif
	return set_bits;
}



static int detect(struct rte_mbuf *pkt) {
	static char flag = 0; 
	uint8_t *msg = rte_pktmbuf_mtod(pkt, uint8_t * );
	uint32_t set_bits = count_bit(msg, pkt->buf_len);
	uint32_t tot_bits = pkt->buf_len * 8;
	p_setbits[pkt_idx % CAPTURE_WINDOWS] = set_bits;
	p_totbits[pkt_idx % CAPTURE_WINDOWS] = tot_bits;
	p_entropy[pkt_idx % CAPTURE_WINDOWS] = ddos_entropy(set_bits, tot_bits);
		if (pkt_idx >= CAPTURE_WINDOWS) {
		int i = 0;
		uint32_t total_set = 0, total_bit = 0;
		double sum_entropy = 0.0;
		for (i = 0;i < CAPTURE_WINDOWS;i ++) {
			total_set += p_setbits[i]; 			total_bit += p_totbits[i]; 			sum_entropy += p_entropy[i];
		}
		double entropy = ddos_entropy(total_set, total_bit);
					if (tresh <  sum_entropy - entropy) { 
			if (!flag) { 								rte_exit(EXIT_FAILURE, "ddos attack !!! Entropy(%f) < Total_Entropy(%f)\n", 
					entropy, sum_entropy);
			}
			flag = 1;
		} else {
			if (flag) { 				
				printf( "no new !!! Entropy(%f) < Total_Entropy(%f)\n", 
					entropy, sum_entropy);
			}
			flag = 0;
		}
		pkt_idx = (pkt_idx+1) % CAPTURE_WINDOWS + CAPTURE_WINDOWS;
	} else {
		pkt_idx ++;
	}
	return 0;
}
#endif
#if ENABLE_TIMER

static void
arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim,
	   void *arg) {
	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
#if 0
	struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, ahdr->arp_data.arp_sha.addr_bytes, 
		ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);
	rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
	rte_pktmbuf_free(arpbuf);
#endif
	int i = 0;
	for (i = 1;i <= 254;i ++) {
		uint32_t dstip = (gLocalIp & 0x00FFFFFF) | (0xFF000000 & (i << 24));
		struct rte_mbuf *arpbuf = NULL;
		uint8_t *dstmac = ng_get_dst_macaddr(dstip);
		if (dstmac == NULL) {
			arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, gLocalIp, dstip);
		} else {
			arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, dstmac, gLocalIp, dstip);
		}
						rte_ring_mp_enqueue_burst(ring_arp, (void**)&arpbuf, 1, NULL);
	}
}
#endif
//网卡聚合函数，参数为rte_mempool，无返回值
void port_bond(struct rte_mempool *mbuf_pool){
		slaves_count = rte_eth_dev_count_avail();
    	uint16_t j;
	RTE_ETH_FOREACH_DEV(j) {
		slave_port_init(j,mbuf_pool);
		slaves[j] = j;
	}
	gLocalIp = MAKE_IPV4_ADDR(192, 168, 31, 110);
    gDefaultArpMac[0] = 0xFF;gDefaultArpMac[1] = 0xFF;gDefaultArpMac[2] = 0xFF;
    gDefaultArpMac[3] = 0xFF;gDefaultArpMac[4] = 0xFF;gDefaultArpMac[5] = 0xFF;
	if (-1 == rte_kni_init(BOND_PORT)) {
		rte_exit(EXIT_FAILURE, "kni init failed\n");
	}
		bond_port_init(mbuf_pool);
		global_kni = ng_alloc_kni(mbuf_pool);
}
//采集模块，主要是封装了dpdk的rx_burst接口，参数与rx_burst一致，返回值返回接收到数据包的个数
unsigned recv_from_port(uint16_t port_id, uint16_t queue_id,
		struct rte_mbuf **mbufs, const uint16_t nb_pkts){
	unsigned num_recvd = rte_eth_rx_burst(BOND_PORT, 0, mbufs, BURST_SIZE);
	if (num_recvd > BURST_SIZE) {
		return -1;
	}
	return num_recvd;
}

bool legal_video(struct rte_mbuf *mbuf)
{
	const char *payload = rte_pktmbuf_mtod(pkt, const char *);
    size_t payload_len = rte_pktmbuf_data_len(pkt);
	const char *content_type_start = strstr(payload, "Content-Type:");
    if (content_type_start != NULL) {
        const char *content_type_end = strchr(content_type_start, '\r');
        if (content_type_end != NULL) {
            size_t content_type_len = content_type_end - content_type_start;
            char content_type[content_type_len + 1];
            rte_memcpy(content_type, content_type_start, content_type_len);
            content_type[content_type_len] = '\0';
                        if (strstr(content_type, "video") != NULL) {
                return 1;             }
        }
    }
    return 0; }
//返回是否符合规则的数据包
bool filter(struct rte_mbuf *mbuf)
{
		struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
	if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
		ng_arp_entry_insert(iphdr->src_addr, ehdr->s_addr.addr_bytes);
		if(iphdr->next_proto_id == IPPROTO_TCP || iphdr->next_proto_id == IPPROTO_UDP){
						if(legal_video(iphdr)){
				return true;
			}
		}
	}
	return false;
}
//视频分流
classify_flow(struct rte_mbuf *mbuf,struct rte_hash *hash)
{
	struct ipv4_5tuple *nk = parse(mbuf);
	uint32_t* tmpdata = (uint32_t *)malloc(sizeof(uint32_t));
	*tmpdata = i;
		rte_hash_add_key_data(hash, nk, (void *)tmpdata);
	struct ipv4_5tuple *key = NULL;
	void *value = NULL;
	uint32_t next =0; 
		while (rte_hash_iterate(hash, (const void **)&key, &value,&next) >= 0){
		if(*(uint32_t*)value % 3 == 0){
						Putflow_with_i(mbuf,0);
		}else if(*(uint32_t*)value % 3 == 1){
						Putflow_with_i(mbuf,1);
		}else{
						Putflow_with_i(mbuf,2);
		}
	}
}

int main(int argc, char *argv[]) {
		dpdk_init();
		int rx_len = 1024
		struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS,
		0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
	}
		port_bond(mbuf_pool);
	#if ENABLE_TIMER
	rte_timer_subsystem_init();
	struct rte_timer arp_timer;
	rte_timer_init(&arp_timer);
	uint64_t hz = rte_get_timer_hz();
	unsigned lcore_id = rte_lcore_id();
	rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, mbuf_pool);
#endif
		lcore_id  = rte_get_next_lcore(lcore_id, 1, 0);
		lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	rte_eal_remote_launch(WRR,mbuf_pool,lcore_id);
		lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	rte_eal_remote_launch(send_pkt,mbuf_pool,lcore_id);
		while (1) {
		struct rte_mbuf *mbufs[BURST_SIZE];
				unsigned num_recvd = recv_from_port(BOND_PORT, 0, mbufs, BURST_SIZE);
#if ENABLE_DETECT
			rx_len = MPC(rx_len);
			unsigned int i = 0;
			for (i = 0;i < num_recvd;i ++) {
				detect(mbufs[i]);
			}
#endif
		unsigned i = 0;
		for (i = 0;i < num_recvd;i ++) {
						if(filter(mbufs[i])){
								classify_flow(mbufs[i],hash);
			}else{
								rte_kni_tx_burst(global_kni, mbufs[i], num_recvd);
			}
		}
	}
        rte_kni_handle_request(global_kni);
#if ENABLE_TIMER
		static uint64_t prev_tsc = 0, cur_tsc;
		uint64_t diff_tsc;
		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if(diff_tsc > TIMER_RESOLUTION_CYCLES) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}
#endif
	DisplayMemoryList();
	}		
}