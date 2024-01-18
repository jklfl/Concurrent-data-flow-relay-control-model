#include "wrr.h"
int calculate_weigth(){
	srand((unsigned)time(NULL));
    int a = rand() % 3;
	return a;
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
void WRR()
{
    int wi;
    int wrr_cost[3];
    int gcd, gcd1, gcd2, maxw, sum;
    int qindex = -1, cw = 0;
    int itr = 0;
    for (wi = 0; wi < 3; wi++) {
        		wrr_cost[wi] = calculate_weigth();
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
								struct _MemoryList* pCurrMemoryList = globalCMemoryPool->m_pMemoryList;
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
