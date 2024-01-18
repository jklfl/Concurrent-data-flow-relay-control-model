#ifndef __INTERFACE_H__
#define __INTERFACE_H__
#include <stdint.h>
#include <sys/file.h>
#include <unistd.h>
#include <pthread.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <netinet/in.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_eth_bond.h>
#include <rte_malloc.h>
#include <rte_timer.h>
#include <time.h>
#include <rte_log.h>
#include <rte_kni.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_arp.h>
#include <rte_spinlock.h>
#include <sys/time.h>
#include <stdio.h>
#include <arpa/inet.h>
#define PID_FILEPATH "/var/run/main.pid"
#define MAX_MEMORYHEAD_SIZE 24         
#define MAGIC_CODE          0x123456   #define MAX_PACKET_SIZE		2048
#define RING_SIZE 			1024
#define UINT32 long long
#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))

struct rte_ring *r1;
struct rte_ring *r2;
struct rte_ring *r3;

struct rte_kni *global_kni;

uint16_t slaves[RTE_MAX_ETHPORTS];
uint16_t slaves_count;
const char *lb_procname;

int BOND_PORT;


struct ipv4_5tuple {
	uint8_t proto;
	uint32_t ip_src;
	uint32_t ip_dst;
	uint16_t port_src;
	uint16_t port_dst;
};

struct _MemoryBlock  
{
	struct _MemoryBlock* m_pNext;
	struct _MemoryBlock* m_pPrev;
	void* m_pBrick;						};

struct _MemoryList					   
{
	struct _MemoryList* m_pMemLNext;
	struct _MemoryBlock* m_pMemoryFree;       
	struct _MemoryBlock* m_pMemoryFreeLast;   
	struct _MemoryBlock* m_pMemoryUsed;       
	struct _MemoryBlock* m_pMemoryUsedLast;   
	struct ipv4_5tuple* flow;
	size_t mbufs_size;
	struct timeval* creat_time;	
};

struct CMemoryPools{
	struct _MemoryList* m_pMemoryList;
	struct _MemoryList* m_pMemoryListLast;
};

struct CMemoryPool_list{
	pthread_mutex_t mute;
	struct CMemoryPools *d[3]; 
};

void proc_check_running();

int Put_flow(void *mbuf,int i);
int Putflow(void *muf,struct CMemoryPools **pl);
int Putflow_with_i(void *muf,int i);
void DisplayMemoryList();
void DisplayMemoryList_pl(struct CMemoryPools *pl);
struct CMemoryPools* GetCMemoryPools();


void WRR();
//WRR_API
int get_gcd(int a, int b);
int get_sum(int wrr_cost[], int wsize);
int get_max(int wrr_cost[], int wsize);
int calculate_weigth();

int ng_config_network_if(uint16_t port_id, uint8_t if_up);
struct rte_kni *ng_alloc_kni(struct rte_mempool *mbuf_pool);
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr);


void Close();
void cclose(struct CMemoryPools **pl);
void CMemoryPools_Init(struct CMemoryPools **pl);
void _MemoryList_Init(struct _MemoryList*);
void _MemoryBlock_Init(struct _MemoryBlock*);
void* SetMemoryHead(void* pBuff, struct _MemoryList* pList,struct _MemoryBlock* pBlock);
void* GetMemoryHead(void* pBuff);
int GetHeadMemoryBlock(void* pBuff,struct _MemoryList** pList,struct _MemoryBlock** pBlock);
struct ipv4_5tuple* parse(void *mbuf);
int is_equel_flow(struct ipv4_5tuple *f1,struct ipv4_5tuple *f2);

int init_ringBuffer();

void dpdk_init();
#endif