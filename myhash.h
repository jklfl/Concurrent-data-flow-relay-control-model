#ifndef __MY_HASH_H__
#define __MY_HASH_H__
#include <stdint.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_jhash.h>
#include <rte_hash.h>
#include <rte_ethdev.h>
#include <stdio.h>
#include <arpa/inet.h>
#define HASH_ENTRI_MAXNUM 1<<12
struct rte_hash * create_hash_table(const char *name);
#endif