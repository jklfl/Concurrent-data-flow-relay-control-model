#include "Interface.h"


void proc_check_running() {
    int fd;
    pid_t pid;
    char buf[32];
    fd = open(PID_FILEPATH, O_RDWR | O_CREAT,0777);
    if (fd < 0) {
        printf("can not open %s\n", PID_FILEPATH);
        exit(-1);
    }
    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        printf("%s is running.\n", lb_procname);
        exit(-1);
    }
    ftruncate(fd, 0);
    lseek(fd, 0, SEEK_SET);
    pid = getpid();
    snprintf(buf, sizeof(buf), "%d", pid);
    if (write(fd, buf, strlen(buf)) < 0) {
        printf("write pid to %s failed.\n", PID_FILEPATH);
        exit(-1);
    }
}
//struct CMemoryPools* globalCMemoryPool = NULL;
struct CMemoryPool_list* pool_list = NULL;
//获取一个缓冲区实例
void GetCMemoryPools_Instance()
{
	if(pool_list == NULL){
		pool_list = (struct CMemoryPool_list*)malloc(sizeof(struct CMemoryPool_list));
		memset(pool_list,0,sizeof(struct CMemoryPool_list));
		pthread_mutex_init(&pool_list->mute, NULL);
	}	
    if(pool_list->d[0] == NULL){
		pthread_mutex_lock(&pool_list->mute);
        pool_list->d[0] = (struct CMemoryPools*)malloc(sizeof(struct CMemoryPools));
		memset(pool_list->d[0],0,sizeof(struct CMemoryPools));
		CMemoryPools_Init(&pool_list->d[0]);
		pthread_mutex_unlock(&pool_list->mute);
    }
	if(pool_list->d[1] == NULL){
		pthread_mutex_lock(&pool_list->mute);
        pool_list->d[1] = (struct CMemoryPools*)malloc(sizeof(struct CMemoryPools));
		memset(pool_list->d[1],0,sizeof(struct CMemoryPools));
		CMemoryPools_Init(&pool_list->d[1]);
		pthread_mutex_unlock(&pool_list->mute);
    }
	if(pool_list->d[2] == NULL){
		pthread_mutex_lock(&pool_list->mute);
        pool_list->d[2] = (struct CMemoryPools*)malloc(sizeof(struct CMemoryPools));
		memset(pool_list->d[2],0,sizeof(struct CMemoryPools));
		CMemoryPools_Init(&pool_list->d[2]);
		pthread_mutex_unlock(&pool_list->mute);
    }
	pthread_mutex_destroy(&pool_list->mute);
}
//初始化缓冲区
void CMemoryPools_Init(struct CMemoryPools **pl)
{
	(*pl)->m_pMemoryList = NULL;
	(*pl)->m_pMemoryListLast = NULL;
}
//初始化memorylist
void _MemoryList_Init(struct _MemoryList* current_list)
{
	current_list->m_pMemLNext         = NULL;
	current_list->m_pMemoryFree       = NULL;
	current_list->m_pMemoryFreeLast   = NULL;
	current_list->m_pMemoryUsed 	  = NULL;
	current_list->m_pMemoryUsedLast   = NULL;
	current_list->flow = NULL;
	current_list->mbufs_size = 0;
	gettimeofday(&current_list->creat_time,NULL);
}
//初始化block
void _MemoryBlock_Init(struct _MemoryBlock* current_block)
{
	current_block->m_pBrick = NULL;
	current_block->m_pNext = NULL;
	current_block->m_pPrev = NULL;
}

void Close(){
	int i = 0;
	for(;i < 3;++i){
		cclose(pool_list->d[i]);
	}
}
//遍历缓冲区并free掉缓冲区申请的所有资源
void cclose(struct CMemoryPools **pl)
{
	struct _MemoryList* pCurrMemoryList = (*pl)->m_pMemoryList;
	while (NULL != pCurrMemoryList)
	{
		struct _MemoryBlock* pMemoryUsed = pCurrMemoryList->m_pMemoryUsed;
		while (NULL != pMemoryUsed)
		{
			if (NULL != pMemoryUsed->m_pBrick)
			{
				free(pMemoryUsed->m_pBrick);
				pMemoryUsed->m_pBrick = NULL;
			}
			pMemoryUsed = pMemoryUsed->m_pNext;
		}
		struct _MemoryBlock* pMemoryFree = pCurrMemoryList->m_pMemoryFree;
		while (NULL != pMemoryFree)
		{
			if (NULL != pMemoryFree->m_pBrick)
			{
				free(pMemoryFree->m_pBrick);
				pMemoryFree->m_pBrick = NULL;
			}
			pMemoryFree = pMemoryFree->m_pNext;
		}
		int temp = pCurrMemoryList;
		pCurrMemoryList = pCurrMemoryList->m_pMemLNext;
		free(temp);
	}
	free(pl);
}
//缓冲块的前三个信息存放当前缓冲块的list，当前block，验证码和真正存放的mbuf
void* SetMemoryHead(void* pBuff,struct _MemoryList* pList,struct _MemoryBlock* pBlock)
{
	if (NULL == pBuff)
	{
		return NULL;
	}
	UINT32* plData = (UINT32*)pBuff;
	plData[0] = (UINT32)pList;         
	plData[1] = (UINT32)pBlock;        
	plData[2] = (UINT32)MAGIC_CODE;    
	return &plData[3];
}
//通过缓冲块获取mbufs
void* GetMemoryHead(void* pBuff)
{
	if (NULL == pBuff)
	{
		return NULL;
	}
	long* plData = (long*)pBuff;
	return &plData[3];
}
//通过缓冲块获取当前的memorylist，当前block。
int GetHeadMemoryBlock(void* pBuff, struct _MemoryList** pList,struct _MemoryBlock** pBlock)
{
	char* szbuf = (char*)pBuff;
	UINT32* plData = (UINT32*)(szbuf - MAX_MEMORYHEAD_SIZE);
	if (plData[2] != (long)MAGIC_CODE)
	{
		return 0;
	}
	else
	{
		*pList = (struct _MemoryList*)plData[0];
		*pBlock = (struct _MemoryBlock*)plData[1];  
		return 1;
	}
}
//通过dpdk的相关api解析mbuf，解析内容为flow五元组。
struct ipv4_5tuple* parse(void* mbuf)
{
	struct rte_mbuf* pbuf = (struct rte_mbuf*)(mbuf);
	struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(pbuf, struct rte_ether_hdr*);
	struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(pbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	struct ipv4_5tuple* flow = (struct ipv4_5tuple *)malloc(sizeof(struct ipv4_5tuple));
	memset(flow,0,sizeof(struct ipv4_5tuple));
	flow->proto = iphdr->next_proto_id;
	flow->ip_src = iphdr->src_addr;
	flow->ip_dst = iphdr->dst_addr;
	if (iphdr->next_proto_id == IPPROTO_UDP) {
		struct rte_udp_hdr* udphdr = (struct rte_udp_hdr*)(iphdr + 1);
		flow->port_src = udphdr->src_port;
		flow->port_dst = udphdr->dst_port;
	}
	else {
		struct rte_tcp_hdr* tcphdr = (struct rte_tcp_hdr*)(iphdr + 1);
		flow->port_src = tcphdr->src_port;
		flow->port_dst = tcphdr->dst_port;
	}
	return flow;
}
//判断两个flow是否相同-------比较五元组
int is_equel_flow(struct ipv4_5tuple *f1,struct ipv4_5tuple *f2)
{
	if(f1->ip_dst != f2->ip_dst){
		return 0;
	}
	if(f1->ip_src != f2->ip_src){
		return 0;
	}
	if(f1->port_dst != f2->port_dst){
		return 0;
	}
	if(f1->port_src != f2->port_src){
		return 0;
	}
	if(f1->proto != f2->proto){
		return 0;
	}
	return 1;
}

int Put_flow(void *mbuf,int i){
	return Putflow(mbuf,&pool_list->d[i]);
}

int Putflow_with_i(void *mbuf,int i){
		return Putflow(mbuf,&pool_list->d[i]);;
}
//存入缓冲区中
int Putflow(void *mbuf,struct CMemoryPools **pl)
{
	void* pBuff = NULL;
	struct rte_mbuf *pbuf= (struct rte_mbuf*)(mbuf);
	struct ipv4_5tuple *flow = parse(pbuf);
	struct in_addr addr;
	addr.s_addr = flow->ip_src;
	printf("flow_src_ip = %s\n",inet_ntoa(addr));
		struct _MemoryList* m_pMemoryList = NULL;
				if (NULL == (*pl)->m_pMemoryList)
	{
		pBuff = malloc(sizeof(struct rte_mbuf) + MAX_MEMORYHEAD_SIZE);
		memset(pBuff,0,sizeof(struct rte_mbuf) + MAX_MEMORYHEAD_SIZE);
		printf("zzzzzzzzzzz\n");
		if (NULL == pBuff)
		{
			return 0;
		}
				m_pMemoryList = (struct _MemoryList*)malloc(sizeof(struct _MemoryList));
		printf("after malloc%x\n",m_pMemoryList);
		memset(m_pMemoryList,0,sizeof(struct _MemoryList));
		if (NULL == m_pMemoryList)
		{
			free(pBuff);
			return 0;
		}
		_MemoryList_Init(m_pMemoryList);
				struct _MemoryBlock* pMemoryUsed = (struct _MemoryBlock*)malloc(sizeof(struct _MemoryBlock));
		memset(pMemoryUsed,0,sizeof(struct _MemoryBlock));
		if (NULL == pMemoryUsed)
		{
			free(pBuff);
			return 0;
		}
		_MemoryBlock_Init(pMemoryUsed);
				pMemoryUsed->m_pBrick = pBuff;
		m_pMemoryList->flow = flow;
				m_pMemoryList->m_pMemoryUsed = pMemoryUsed;
		m_pMemoryList->m_pMemoryUsedLast = pMemoryUsed;
		m_pMemoryList->mbufs_size++;
				(*pl)->m_pMemoryList = m_pMemoryList;
		(*pl)->m_pMemoryListLast = m_pMemoryList;
		*(struct rte_mbuf*)SetMemoryHead(pBuff, m_pMemoryList, pMemoryUsed) = *pbuf;
		return 1;
	}
		struct _MemoryList* pCurrMemoryList = (*pl)->m_pMemoryList;
	while(NULL != pCurrMemoryList)
	{
				if(is_equel_flow(pCurrMemoryList->flow,flow) && pCurrMemoryList->mbufs_size < 10)
		{
			struct _MemoryBlock* pMemoryFree = pCurrMemoryList->m_pMemoryFree;
			if(NULL == pMemoryFree)
			{
				pBuff = malloc(sizeof(struct rte_mbuf) + MAX_MEMORYHEAD_SIZE);
				memset(pBuff,0,sizeof(struct rte_mbuf) + MAX_MEMORYHEAD_SIZE);
				if(NULL == pBuff)
				{
					return NULL;
				}
				struct _MemoryBlock* pMemoryUsed = (struct _MemoryBlock*)malloc(sizeof(struct _MemoryBlock));
				memset(pMemoryUsed,0,sizeof(struct _MemoryBlock));
				if(NULL == pMemoryUsed)
				{
					free(pBuff);
					return NULL;
				}
				_MemoryBlock_Init(pMemoryUsed);
				pMemoryUsed->m_pBrick = pBuff;
				struct _MemoryBlock* pMemoryUsedLast = (*pl)->m_pMemoryList->m_pMemoryUsedLast;
				if(NULL == pMemoryUsedLast)
				{
										pCurrMemoryList->flow = flow;
					pCurrMemoryList->m_pMemoryUsed     = pMemoryUsed;
					pCurrMemoryList->m_pMemoryUsedLast = pMemoryUsed;
					pCurrMemoryList->mbufs_size++;
					*(struct rte_mbuf*)SetMemoryHead(pBuff, pCurrMemoryList, pMemoryUsed) = *pbuf;
					return 1;
				}
				else
				{
					pMemoryUsed->m_pPrev                        = pCurrMemoryList->m_pMemoryUsedLast;
					pCurrMemoryList->m_pMemoryUsedLast->m_pNext = pMemoryUsed;
					pCurrMemoryList->m_pMemoryUsedLast          = pMemoryUsed;
					pCurrMemoryList->mbufs_size++;
					*(struct rte_mbuf*)SetMemoryHead(pBuff, pCurrMemoryList, pMemoryUsed) = *pbuf;
					return 1;
				}
			}
			else
			{
				struct _MemoryBlock* pMemoryTemp      = pMemoryFree;
				pCurrMemoryList->m_pMemoryFree = pMemoryFree->m_pNext;
				pBuff                          = pMemoryTemp->m_pBrick;
				pMemoryTemp->m_pPrev                        = pCurrMemoryList->m_pMemoryUsedLast;
				pMemoryFree->m_pNext                        = NULL;
				if(NULL == pCurrMemoryList->m_pMemoryUsedLast)
				{
					pCurrMemoryList->m_pMemoryUsedLast          = pMemoryTemp;
					pCurrMemoryList->m_pMemoryUsed              = pMemoryTemp;
				}
				else
				{
					pCurrMemoryList->m_pMemoryUsedLast->m_pNext = pMemoryTemp;
					pCurrMemoryList->m_pMemoryUsedLast          = pMemoryTemp;
				}
				*(struct rte_mbuf*)GetMemoryHead(pBuff) = *pbuf;
				return 1;
			}
		}
		else
		{
			pCurrMemoryList = pCurrMemoryList->m_pMemLNext;
		}
	}
	printf("over 10 size\n");
			printf("new\n");
	pBuff = malloc(sizeof(struct rte_mbuf) + MAX_MEMORYHEAD_SIZE);
	memset(pBuff,0,sizeof(struct rte_mbuf) + MAX_MEMORYHEAD_SIZE);
	if (NULL == pBuff)
	{
		return 0;
	}
		struct _MemoryList  *pMemoryList = (struct _MemoryList*)malloc(sizeof(struct _MemoryList));
	memset(pMemoryList,0,sizeof(struct _MemoryList));
	if (NULL == pMemoryList)
	{
		free(pBuff);
		return 0;
	}
	_MemoryList_Init(pMemoryList);
		struct _MemoryBlock* pMemoryUsed = (struct _MemoryBlock*)malloc(sizeof(struct _MemoryBlock));
	memset(pMemoryUsed,0,sizeof(struct _MemoryBlock));
	if (NULL == pMemoryUsed)
	{
		free(pBuff);
		return 0;
	}
	_MemoryBlock_Init(pMemoryUsed);
		pMemoryUsed->m_pBrick = pBuff;
	pMemoryList->flow = flow;
		pMemoryList->m_pMemoryUsed = pMemoryUsed;
	pMemoryList->m_pMemoryUsedLast = pMemoryUsed;
	pMemoryList->mbufs_size++;
		(*pl)->m_pMemoryListLast->m_pMemLNext = pMemoryList;
	(*pl)->m_pMemoryListLast = pMemoryList;
	*(struct rte_mbuf*)SetMemoryHead(pBuff, pMemoryList, pMemoryUsed) = *pbuf;
	return 1;
}


void DisplayMemoryList()
{
	int i = 0;
	for(int i = 0;i < 3;++i){
		printf("this is %d cache",i);
		DisplayMemoryList_pl(pool_list->d[i]);
	}
}
// 通过链表操作,打印所有memorylist和memorylist中block
void DisplayMemoryList_pl(struct CMemoryPools *pl)
{
	int nUsedCount = 0;
	int nFreeCount = 0;
	int n = 1;
	struct _MemoryList* pCurrMemoryList = pl->m_pMemoryList;
	while (NULL != pCurrMemoryList)
	{
		printf("the %d numebr list \n",n);
		struct _MemoryBlock* pMemoryUsed = pCurrMemoryList->m_pMemoryUsed;
		struct _MemoryBlock* pMemoryFree = pCurrMemoryList->m_pMemoryFree;
		nUsedCount = 0;
		nFreeCount = 0;
		while (NULL != pMemoryUsed)
		{
			nUsedCount++;
			struct rte_mbuf *mbuf = (struct rte_mbuf*)GetMemoryHead(pMemoryUsed->m_pBrick); 
			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
			if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				continue;
			}
			struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
			if (iphdr->next_proto_id == IPPROTO_UDP) {
				struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);
				uint16_t length = ntohs(udphdr->dgram_len);
				*((char*)udphdr + length) = '\0';
				struct in_addr addr;
				addr.s_addr = iphdr->src_addr;
				printf("src: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));
				addr.s_addr = iphdr->dst_addr;
				printf("dst: %s:%d, %s\n", inet_ntoa(addr), ntohs(udphdr->dst_port), 
					(char *)(udphdr+1));
			}
			pMemoryUsed = pMemoryUsed->m_pNext;
		}
		struct in_addr addr;
		addr.s_addr = pCurrMemoryList->flow->ip_src;
		printf("flow_src_ip = %s pMemoryUsed nUsedCount = %d\n",inet_ntoa(addr), nUsedCount);
		while (NULL != pMemoryFree)
		{
			nFreeCount++;
			pMemoryFree = pMemoryFree->m_pNext;
		}
		printf("flow_src_ip = %s pMemoryFree nFreeCount = %d\n",inet_ntoa(addr), nFreeCount);
		n++;
		pCurrMemoryList = pCurrMemoryList->m_pMemLNext;
	}
}

int get_gcd(int a, int b)
{
     return b ? get_gcd(b, a % b) : a;
}

int get_sum(int wrr_cost[], int wsize)
{
    int i, sum = 0;
    for (i = 0; i < wsize; i++)
        sum += wrr_cost[i];
    return sum;
}

int get_max(int wrr_cost[], int wsize) 
{
    int maxw = 0, i;
    for (i = 0; i < wsize; i++) {
        if (i == 0) 
            maxw = wrr_cost[i];
        else if (wrr_cost[i] > maxw) 
            maxw = wrr_cost[i];
    }
    return maxw;
}

int init_ringBuffer(){
	r1 = rte_ring_create("r1", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	r2 = rte_ring_create("r2", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	r3 = rte_ring_create("r3", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	if(!r1 || !r2 || !r3){
		rte_exit(EXIT_FAILURE, "Could not create ringBuffer\n");
	}
}

int calculate_weigth(int wid){
	    		int size = pool_list->d[wid]->m_pMemoryList->mbufs_size;
	struct timeval* now_time = (struct timeval*)malloc(sizeof(struct timeval));
	gettimeofday(&now_time,NULL);
	double time1, time2;
    time1 = now_time->tv_sec + (now_time->tv_usec / 1000000.0);
    time2 = pool_list->d[wid]->m_pMemoryList->creat_time->tv_sec + (pool_list->d[wid]->m_pMemoryList->creat_time->tv_usec / 1000000.0);
    time1 = time1 - time2;
	return 0.5 * size + 0.5 * time1;
}
//WRR调度算法
void WRR()
{
    int wi;
    int wrr_cost[3];
    int gcd, gcd1, gcd2, maxw, sum;
    int qindex = -1, cw = 0;
    int itr = 0;
    for (wi = 0; wi < 3; wi++) {
        		wrr_cost[wi] = calculate_weigth(wi);
    }
    maxw = get_max(wrr_cost, 3);
    sum = get_sum(wrr_cost, 3);
    gcd1 = get_gcd(wrr_cost[0], wrr_cost[1]);
    gcd2 = get_gcd(wrr_cost[2], wrr_cost[3]);
    gcd = get_gcd(gcd1, gcd2);
	while(1){
        while (1) {
            qindex = (qindex + 1) % 3;
            if (qindex == 0) {
                cw = cw - gcd;
                if (cw <= 0) {
                    cw = maxw;
                    if (cw == 0)
                        break;
                }
            }
            if (wrr_cost[qindex] >= cw) {
								struct _MemoryList* pCurrMemoryList = pl->m_pMemoryList;
				while (NULL != pCurrMemoryList){
					struct _MemoryBlock* pMemoryUsed = pCurrMemoryList->m_pMemoryUsed;
					struct rte_mbuf *mbuf = (struct rte_mbuf*)GetMemoryHead(pMemoryUsed->m_pBrick); 
					if(qindex == 1){
						rte_ring_mp_enqueue_burst(r1, (void**)mbuf, 1, NULL);
					}else if(qindex == 2){
						rte_ring_mp_enqueue_burst(r2, (void**)mbuf, 1, NULL);
					}else{
						rte_ring_mp_enqueue_burst(r3, (void**)mbuf, 1, NULL);
					}
					pCurrMemoryList = pCurrMemoryList->m_pMemLNext;
					}
				}
                printf("Queues selected: %s\n", qindex);
                break;
		}
	}
}
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}


int ng_config_network_if(uint16_t port_id, uint8_t if_up) {
	if (!rte_eth_dev_is_valid_port(port_id)) {
		return -EINVAL;
	}
	int ret = 0;
	if (if_up) {
		rte_eth_dev_stop(port_id);
		ret = rte_eth_dev_start(port_id);
	} else {
		rte_eth_dev_stop(port_id);
	}
	if (ret < 0) {
		printf("Failed to start port : %d\n", port_id);
	}
	return 0;
}

struct rte_kni *ng_alloc_kni(struct rte_mempool *mbuf_pool) {
	struct rte_kni *kni_hanlder = NULL;
	struct rte_kni_conf conf;
	memset(&conf, 0, sizeof(conf));
	snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%u", BOND_PORT);
	conf.group_id = BOND_PORT;
	conf.mbuf_size = MAX_PACKET_SIZE;
	rte_eth_macaddr_get(BOND_PORT, (struct rte_ether_addr *)conf.mac_addr);
	rte_eth_dev_get_mtu(BOND_PORT, &conf.mtu);
	print_ethaddr("ng_alloc_kni: ", (struct rte_ether_addr *)conf.mac_addr);
	struct rte_kni_ops ops;
	memset(&ops, 0, sizeof(ops));
	ops.port_id = BOND_PORT;
	ops.config_network_if = ng_config_network_if;
	kni_hanlder = rte_kni_alloc(mbuf_pool, &conf, &ops);	
	if (!kni_hanlder) {
		rte_exit(EXIT_FAILURE, "Failed to create kni for port : %d\n", BOND_PORT);
	}
	return kni_hanlder;
}
//dpdk初始化，无参数和返回值
void dpdk_init(){
	proc_check_running();
	if (rte_eal_init(argc, argv) < 0) {
		rte_exit(EXIT_FAILURE, "Error with EAL init\n");
	}
	rte_pdump_init(NULL);
		GetCMemoryPools_Instance();
		struct rte_hash *hash  = create_hash_table("cuckoo hash table");
}