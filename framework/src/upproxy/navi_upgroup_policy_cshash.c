/*
 * navi_upgroup_policy_cshash.c
 *  consistence hash policy
 *  Created on: 2014-01-20
 *      Author: yanguotao@youku.com
 */

#include "navi_upgroup_policy_cshash.h"
#include "navi_upserver.h"
#include "navi_frame_log.h"
#include "navi_list.h"
#include "md5.h"
#include <math.h>

#define NVUP_POLICY_CSHASH_KEY "cshash_key"
#define NVUP_POLICY_CSHASH_PREFIX_FLAG   "cshash_prefix_flag"
#define NVUP_POLICY_CSHASH_POINTS_PER_SERVER    160 /* 40 points per hash */

typedef struct navi_upserver_policy_cshash_s
{
	uint32_t weight;
} navi_upserver_policy_cshash_t;

typedef struct navi_upgroup_policy_ring_s
{	navi_upserver_t* server;
	unsigned int point;
} navi_upgroup_policy_ring_t;

typedef struct navi_upgroup_policy_cshash_s
{
	navi_upgroup_policy_ring_t *ring;
	unsigned int points;
	unsigned int ring_sz;
} navi_upgroup_policy_cshash_t;

static int navi_upgroup_policy_ring_cmp(const void *a, const void *b)
{
	navi_upgroup_policy_ring_t* a1 = (navi_upgroup_policy_ring_t*)a;
	navi_upgroup_policy_ring_t* b1 = (navi_upgroup_policy_ring_t*)b;
	if (a1->point < b1->point){
		return -1;
	}
	else if (a1->point > b1->point){
		return 1;
	}
	else{
		return 0;
	}
}

static void str_md5(char* str, unsigned char md5[16]){
	md5_state_t md5state;
	md5_init( &md5state );
	md5_append( &md5state,(unsigned char *)str,strlen(str));
	md5_finish( &md5state,md5 );
}

static unsigned int strkey_hash(char* strkey)
{
    unsigned char digest[16];
    str_md5(strkey,digest);
    return (unsigned int)((digest[3] << 24)|
						(digest[2] << 16)|
						(digest[1] <<  8)|
						digest[0] );
}

NAVI_UPGROUP_POLICY_INIT_FUNC(cshash, impl, cfg)
{
	navi_upgroup_t* upgrp = impl->group;
	navi_hash_t* upservers = upgrp->s.hash;
	if (!upservers || upservers->used == 0) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "upgroup:%s server empty",
		    upgrp->group_name);
		return NAVI_INNER_ERR;
	}

	chain_node_t* nd = upservers->list_link.next;
	navi_hent_t* he;
	navi_upserver_policy_cshash_t* srv_data;
	int total_weight = 0;
	int weight_cnt = 0;
	int av_weight = 100;
	int server_cnt = 0;
	int i = 0, h=0, cnt=0;
	char key[256];
	unsigned char digest[16];
	navi_upserver_t* srv;
	while (nd != &upservers->list_link) {
		he = (navi_hent_t*) ((char*) nd - offsetof(navi_hent_t,list_link));
		srv = (navi_upserver_t*) he->v;
		srv_data = (navi_upserver_policy_cshash_t*)srv->policy_settings.data;
		if (srv_data->weight > 0){
			total_weight += srv_data->weight;
			weight_cnt++;
		}
		server_cnt++;
		nd = nd->next;
	}
	if (total_weight > 0){
		av_weight = (int)(total_weight/weight_cnt);
	}

	total_weight = 0;
	nd = upservers->list_link.next;
	while (nd != &upservers->list_link) {
		he = (navi_hent_t*) ((char*) nd - offsetof(navi_hent_t,list_link));
		srv = (navi_upserver_t*) he->v;
		srv_data = (navi_upserver_policy_cshash_t*)srv->policy_settings.data;
		if (srv_data->weight <= 0){
			srv_data->weight = av_weight;
		}
		total_weight += srv_data->weight;
		nd = nd->next;
	}
	
	size_t ring_sz = server_cnt*NVUP_POLICY_CSHASH_POINTS_PER_SERVER;

	navi_upgroup_policy_cshash_t* grp_data = navi_pool_calloc(upgrp->pool, 1,
		sizeof(navi_upgroup_policy_cshash_t));

	impl->data = grp_data;
	grp_data->ring = navi_pool_calloc(upgrp->pool, ring_sz+1, sizeof(navi_upgroup_policy_ring_t));
	grp_data->ring_sz = ring_sz;

	nd = upservers->list_link.next;
	while (nd != &upservers->list_link) {
		he = (navi_hent_t*) ((char*) nd - offsetof(navi_hent_t,list_link));
		srv = (navi_upserver_t*) he->v;
		srv_data = (navi_upserver_policy_cshash_t*)srv->policy_settings.data;

		float r = (float)srv_data->weight / (float)total_weight;
		unsigned int s = floorf(r * 40.0 * (float)server_cnt);
		for (i = 0; i < s; i++){
			sprintf(key,"%s%d", srv->server_name, i);
			str_md5(key,digest);
			for (h = 0; h < 4; h++){
				grp_data->ring[cnt].point = (digest[3+h*4] << 24 )|
											(digest[2+h*4] << 16 )|
											(digest[1+h*4] <<  8 )|
											digest[h*4];
				grp_data->ring[cnt].server = srv;
				cnt++;
			}
		}
		nd = nd->next;
	}
	qsort((void*)(grp_data->ring), cnt, sizeof(navi_upgroup_policy_ring_t), navi_upgroup_policy_ring_cmp);
	grp_data->points = cnt;
	
	return NAVI_OK;
}

NAVI_UPGROUP_POLICY_RESOLVE_FUNC(cshash, impl, req)
{
	navi_upgroup_policy_cshash_t* grp_data = impl->data;
	navi_upgroup_t* upgrp = impl->group;
	const char *key;
	json_t *je;

	if (req->srv_name){
		return navi_upgroup_get_server(upgrp, req->srv_name);
	}

	if (req->proto == NVUP_PROTO_REDIS){
		key = navi_upreq_get_policy_key(req, "key");
	}
	else{
		je = json_object_get(upgrp->c.config, NVUP_POLICY_CSHASH_KEY);
		if (!je || !json_is_string(je) || strlen(json_string_value(je)) == 0) {
			NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    		"upgroup policy resolve: %s is absent. Conf:%s.", NVUP_POLICY_CSHASH_KEY, upgrp->c.config_path);
			return NULL;
		}
		const char* key_name = json_string_value(je);
		key = navi_upreq_get_policy_key(req, key_name);
	}
	if (key == NULL){
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    		"upgroup policy resolve: can not get key for policy resolve.");
		return NULL;
	}
	if (grp_data->points <= 0){
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    		"upgroup policy resolve: consitence hash total points must be positive.");
		return NULL;
	}

	je = json_object_get(upgrp->c.config, NVUP_POLICY_CSHASH_PREFIX_FLAG);
	char tmp = '\0';
	char *p = NULL;
	if (je && json_is_string(je) ) {
		const char *prefix_flag = json_string_value(je);
		if (strlen(prefix_flag)){
			p = strstr(key, prefix_flag);
			if (p != NULL){
				tmp = *p;
				*p = '\0';
			}
		}
	}

	unsigned int hash = strkey_hash((char *)key);
	if (p != NULL){
		*p = tmp;
	}
    	navi_upgroup_policy_ring_t *begin, *end, *left, *right, *middle;
	
	begin = left = &(grp_data->ring[0]);
	end = right = begin+grp_data->points;

	while (left < right) {
		middle = left + (right - left) / 2;
		if (middle->point < hash) {
			left = middle + 1;
		} else {
			right = middle;
		}
	}

	if (right == end) {
		right = begin;
	}

	return right->server;
}

NAVI_UPGROUP_POLICY_QUERY_FUNC(cshash, impl, in_keys, policy)
{
	navi_upgroup_policy_cshash_t* grp_data = impl->data;
	navi_upgroup_t* upgrp = impl->group;
	json_t *je;
	if (navi_list_empty(in_keys)){
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    		"upgroup policy query: inkeys invalid for polkicy query.");
		return NULL;
	}
	nvup_policy_inkey_t *inkey = navi_list_data(in_keys->next, nvup_policy_inkey_t, link);
	const char *key = inkey->v;
	if (key == NULL){
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    		"upgroup policy query: can not get key for policy query.");
		return NULL;
	}
	if (grp_data->points <= 0){
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    		"upgroup policy query: consitence hash total points must be positive.");
		return NULL;
	}

	je = json_object_get(upgrp->c.config, NVUP_POLICY_CSHASH_PREFIX_FLAG);
	char tmp = '\0';
	char *p = NULL;
	if (je && json_is_string(je) ) {
		const char *prefix_flag = json_string_value(je);
		if (strlen(prefix_flag)){
			p = strstr(key, prefix_flag);
			if (p != NULL){
				tmp = *p;
				*p = '\0';
			}
		}
	}

	unsigned int hash = strkey_hash((char *)key);
	if (p != NULL){
		*p = tmp;
	}
    	navi_upgroup_policy_ring_t *begin, *end, *left, *right, *middle;
	
	begin = left = &(grp_data->ring[0]);
	end = right = begin+grp_data->points;

	while (left < right) {
		middle = left + (right - left) / 2;
		if (middle->point < hash) {
			left = middle + 1;
		} else {
			right = middle;
		}
	}

	if (right == end) {
		right = begin;
	}

	return right->server;
}
	
NAVI_UPGROUP_POLICY_DESTROY_FUNC(cshash, impl)
{
	return;
}

NAVI_UPSERVER_POLICY_INIT_FUNC(cshash, srv, srv_cfg)
{
	json_t* je = json_object_get(srv_cfg, "weight");
	int tw = 1;
	if (je && json_is_integer(je)) {
		tw = json_integer_value(je);
		if (tw <= 0)
			tw = 1;
	}

	navi_upserver_policy_cshash_t* data = navi_pool_calloc(srv->pool, 1,
		sizeof(navi_upserver_policy_cshash_t));

	data->weight = tw;
	srv->policy_settings.data = data;
	return NAVI_OK;
}
