/*
 * navi_upgroup_policy_rr.c
 *
 *  Created on: 2013-12-10
 *      Author: li.lei
 */

#include "navi_upgroup_policy_rr.h"
#include "navi_upserver.h"
#include "navi_frame_log.h"

typedef struct navi_upserver_policy_rr_s
{
	uint32_t weight;
} navi_upserver_policy_rr_t;

typedef struct navi_upgroup_policy_rr_s
{
	uint32_t last_select;
	navi_upserver_t** ring;
	size_t ring_sz;
} navi_upgroup_policy_rr_t;

NAVI_UPGROUP_POLICY_INIT_FUNC(rr, impl, cfg)
{
	navi_upgroup_t* upgrp = impl->group;
	navi_hash_t* upservers = upgrp->s.hash;
	if (!upservers || upservers->used == 0) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "upgroup:%s server empty",
		    upgrp->group_name);
		return NAVI_INNER_ERR;
	}

	srand(time());

	//chain_node_t* nd = upservers->list_link.next;
	navi_hent_t* he;
	navi_upserver_policy_rr_t* srv_data;
	int total_weight = 0;
	int dup_multi = 1;
	navi_upserver_t* srv;
	void* it = navi_hash_iter(upservers);
	while ((he=navi_hash_iter_next(it))) {
		srv = (navi_upserver_t*) he->v;
		srv_data = (navi_upserver_policy_rr_t*)srv->policy_settings.data;
		total_weight += srv_data->weight;
	}
	navi_hash_iter_destroy(it);

	if ( total_weight/upservers->used < 10 ) {
		dup_multi = total_weight/upservers->used * 10;
	}

	size_t ring_sz = dup_multi*total_weight;

	navi_upgroup_policy_rr_t* grp_data = navi_pool_calloc(upgrp->pool, 1,
		sizeof(navi_upgroup_policy_rr_t));

	impl->data = grp_data;
	grp_data->last_select = 0;
	grp_data->ring = navi_pool_calloc(upgrp->pool, dup_multi*total_weight,
		sizeof(navi_upserver_t*));

	navi_upserver_t** cur = grp_data->ring;
	it = navi_hash_iter(upservers);
	while ((he=navi_hash_iter_next(it))) {
		srv = (navi_upserver_t*) he->v;
		srv_data = (navi_upserver_policy_rr_t*)srv->policy_settings.data;
		int i,j;
		for ( i = 0; i < srv_data->weight; i++ ) {
			for ( j = 0; j < dup_multi; j++ )
				*cur++ = srv;
		}
	}
	navi_hash_iter_destroy(it);

	int i, swpa, swpb;
	navi_upserver_t* swp;
	for ( i=0; i<ring_sz; i++) {
		swpa = rand()%ring_sz;
		swpb = rand()%ring_sz;
		if (swpa != swpb) {
			swp = grp_data->ring[swpa];
			grp_data->ring[swpa] = grp_data->ring[swpb];
			grp_data->ring[swpb] = swp;
		}
	}

	grp_data->ring_sz = ring_sz;
	return NAVI_OK;
}

NAVI_UPGROUP_POLICY_RESOLVE_FUNC(rr, impl, req)
{
	navi_upgroup_policy_rr_t* grp_data = impl->data;
	navi_upgroup_t* upgrp = impl->group;

	if (req->srv_name){
		return navi_upgroup_get_server(upgrp, req->srv_name);
	}
	navi_upserver_t* ret = grp_data->ring[grp_data->last_select];
	grp_data->last_select = (grp_data->last_select+1) % grp_data->ring_sz;
	return ret;
}

NAVI_UPGROUP_POLICY_DESTROY_FUNC(rr, impl)
{
	return;
}

NAVI_UPSERVER_POLICY_INIT_FUNC(rr, srv, srv_cfg)
{
	json_t* je = json_object_get(srv_cfg, "weight");
	int tw = 1;
	if (je && json_is_integer(je)) {
		tw = json_integer_value(je);
		if (tw <= 0)
			tw = 1;
	}

	navi_upserver_policy_rr_t* data = navi_pool_calloc(srv->pool, 1,
		sizeof(navi_upserver_policy_rr_t));

	data->weight = tw;
	srv->policy_settings.data = data;
	return NAVI_OK;
}
