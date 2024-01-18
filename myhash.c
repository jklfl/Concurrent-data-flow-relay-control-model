#include "Interface.h"
#include "myhash.h"
#define HASH_ENTRI_MAXNUM 1<<12
#define HUSH_KEY_COUNT   1<< 4
struct rte_hash * create_hash_table(const char *name){
	struct rte_hash_parameters *param = (struct rte_hash_parameters *) malloc(sizeof(struct rte_hash_parameters));
	if (!param) return NULL;
	param->name = name;
	param->entries = HASH_ENTRI_MAXNUM;
	param->key_len = sizeof(struct ipv4_5tuple);
	param->hash_func = rte_jhash; 					 	param->hash_func_init_val = 0;
	param->socket_id =rte_socket_id();               	
	struct rte_hash *hash = rte_hash_create(param);
	if (hash == NULL) {
		rte_exit(EXIT_FAILURE, "Could not create HASH\n");		
	}
	return hash;
}