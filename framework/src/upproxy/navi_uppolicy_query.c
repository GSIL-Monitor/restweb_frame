/*
 * navi_uppolicy_batch.c
 *
 *  Created on: 2013-12-25
 *      Author: li.lei
 */

#include "navi_uppolicy_query.h"
#include "navi_upgroup_mgr.h"
#include "navi_upgroup.h"
#include "navi_frame_log.h"

#define NVUP_POLICY_BQUERY_OBJ_SZ  (sizeof(navi_uppolicy_bquery_t)+0x100)
#define NVUP_POLICY_SQUERY_OBJ_SZ  (sizeof(navi_uppolicy_squery_t)+0x100)

navi_uppolicy_bquery_t* navi_uppolicy_bquery_create()
{
	navi_uppolicy_bquery_t* obj = (navi_uppolicy_bquery_t*) calloc(1,
		NVUP_POLICY_BQUERY_OBJ_SZ);

	if (!obj)
		return NULL;

	navi_pool_init(obj->pool, obj, 0x100);
	return obj;
}

static void clean_policies(navi_array_t* a_policies)
{
	int pt, i;
	for (pt = 0; pt < a_policies->part_size; pt++) {
		if (a_policies->parts[pt] == NULL)
			break;
		navi_array_part_t* part = a_policies->parts[pt];
		nvup_policy_keygroup_t* grp = (nvup_policy_keygroup_t*) part->allocs;
		for (i = 0; i < part->used; i++, grp++) {
			if (grp->policy.gr_data)
				json_decref(grp->policy.gr_data);
		}
	}
}

void navi_uppolicy_bquery_destroy(navi_uppolicy_bquery_t* obj)
{
	if (obj)
	{
		if (obj->a_policies)
			clean_policies(obj->a_policies);
		navi_pool_destroy(obj->pool);
	}
}

nvup_policy_inkeys_t* navi_uppolicy_bquery_new_inkeys(navi_uppolicy_bquery_t* obj)
{
	if (!obj)
		return NULL;
	if (obj->a_keys == NULL) {
		obj->a_keys = (navi_array_t*) navi_array_create(obj->pool, 2, sizeof(nvup_policy_inkeys_t));
		if (obj->a_keys == NULL)
			return NULL;
	}

	nvup_policy_inkeys_t* inkeys = navi_array_push(obj->a_keys);
	inkeys->next = inkeys->prev = inkeys;
	return inkeys;
}

void navi_uppolicy_bquery_add_inkey(navi_uppolicy_bquery_t* obj, nvup_policy_inkeys_t* keys,
    const char* k, const char* v)
{
	if (!obj || !keys || !k)
		return;

	nvup_policy_inkey_t* key = (nvup_policy_inkey_t*) navi_pool_calloc(obj->pool, 1,
	    sizeof(nvup_policy_inkey_t));
	key->k = navi_pool_strdup(obj->pool, k);
	if (v)
		key->v = navi_pool_strdup(obj->pool, v);
	else
		key->v = NULL;

	key->link.prev = keys->prev;
	key->link.next = keys;
	keys->prev->next = &key->link;
	keys->prev = &key->link;

	return;
}

void* navi_uppolicy_query_inkey_iter(nvup_policy_inkeys_t* keys)
{
	if (!keys)
		return NULL;
	return keys->next;
}

void* navi_uppolicy_query_inkey_next(nvup_policy_inkeys_t* keys, void* iter,
    const char** ok, const char** ov)
{
	chain_node_t* cur = (chain_node_t*) iter;
	if (!keys || !ok || !ov || !cur || cur == keys)
		return NULL;
	nvup_policy_inkey_t* k = (nvup_policy_inkey_t*)
	    ((char*) cur - offsetof(nvup_policy_inkey_t, link));
	*ok = k->k;
	*ov = k->v;
	return cur->next;
}

const char* navi_uppolicy_query_getkey(nvup_policy_inkeys_t* keys, const char* key)
{
	if (!keys || !key)
		return NULL;
	chain_node_t* link = keys->next;
	nvup_policy_inkey_t* nd;
	while (link != keys) {
		nd = (nvup_policy_inkey_t*) ((char*) link - offsetof(nvup_policy_inkey_t, link));
		if (!strcmp(key, nd->k))
			return nd->v;
		link = link->next;
	}
	return NULL;
}

static nvup_policy_keygroup_t* get_keygroup(navi_uppolicy_bquery_t* obj, const char* srv_name)
{
	int pt, i;
	for (pt = 0; pt < obj->a_policies->part_size; pt++) {
		if (obj->a_policies->parts[pt] == NULL)
			break;
		navi_array_part_t* part = obj->a_policies->parts[pt];
		nvup_policy_keygroup_t* grp = (nvup_policy_keygroup_t*) part->allocs;
		for (i = 0; i < part->used; i++, grp++) {
			if (!strcmp(grp->policy.server_name, srv_name))
				return grp;
		}
	}

	return NULL;
}

static nvup_policy_keygroup_t* new_keygroup(navi_uppolicy_bquery_t* obj, const char* srv_name,
    const navi_upreq_policy_t* tmp)
{
	if (obj->a_policies == NULL) {
		obj->a_policies = navi_array_create(obj->pool, 4, sizeof(nvup_policy_keygroup_t));
		if (obj->a_policies == NULL)
			return NULL;
	}

	nvup_policy_keygroup_t* p = navi_array_push(obj->a_policies);
	if (!p)
		return NULL;

	memset(p, 0x00, sizeof(nvup_policy_keygroup_t));
	p->policy = *tmp;
	return p;
}

static void append_keygroup(navi_uppolicy_bquery_t* obj,
    nvup_policy_keygroup_t* grp, nvup_policy_inkeys_t* inkeys)
{
	if (grp->inkeys_group == NULL) {
		grp->inkeys_group = navi_array_create(obj->pool, 16, sizeof(nvup_policy_inkeys_t*));
		if (!grp->inkeys_group)
			return;
	}
	nvup_policy_inkeys_t** pp = navi_array_push(grp->inkeys_group);
	if (pp)
		*pp = inkeys;
	return;
}

static void append_failed_keygroup(navi_uppolicy_bquery_t* obj, nvup_policy_inkeys_t* inkeys)
{
	if (obj->failed_keys == NULL) {
		obj->failed_keys = navi_array_create(obj->pool, 4, sizeof(nvup_policy_inkeys_t*));
		if (obj->failed_keys == NULL)
			return;
	}
	nvup_policy_inkeys_t** pp = navi_array_push(obj->failed_keys);
	if (pp)
		*pp = inkeys;
	return;
}

int navi_uppolicy_bquery_resolve(navi_uppolicy_bquery_t* obj, const char* upgroup)
{
	navi_upgroup_mgr_t* mgr = navi_upgroup_mgr_instance(NULL);
	if (!mgr)
		return NAVI_INNER_ERR;

	navi_upgroup_t* grp = (navi_upgroup_t*) navi_hash_get_gr(mgr->groups, upgroup);
	if (!grp)
		return NAVI_ARG_ERR;

	nvup_policy_keygroup_t* key_grp;
	navi_upreq_policy_t tmp_result;

	int pt, i;
	for (pt = 0; pt < obj->a_keys->part_size; pt++) {
		if (obj->a_keys->parts[pt] == NULL)
			break;

		navi_array_part_t* part = obj->a_keys->parts[pt];
		nvup_policy_inkeys_t* inkeys = (nvup_policy_inkeys_t*) part->allocs;
		for (i = 0; i < part->used; i++) {
			memset(&tmp_result, 0x00, sizeof(navi_upreq_policy_t));
			tmp_result.pool = obj->pool;
			if (NAVI_OK == navi_upgroup_policy_query(grp, inkeys, &tmp_result)) {
				key_grp = get_keygroup(obj, tmp_result.server_name);
				if (!key_grp) {
					key_grp = new_keygroup(obj, tmp_result.server_name, &tmp_result);
					if (!key_grp)
						return NAVI_INNER_ERR;
					append_keygroup(obj, key_grp, inkeys);
				}
				else {
					if (tmp_result.gr_data)
						json_decref(tmp_result.gr_data);
					append_keygroup(obj, key_grp, inkeys);
				}
			}
			else {
				append_failed_keygroup(obj, inkeys);
			}
			inkeys += 1;
		}
	}

	return NAVI_OK;
}

nvup_policy_keygroup_t* navi_uppolicy_bquery_get_group(navi_uppolicy_bquery_t* obj, int idx)
{
	return (nvup_policy_keygroup_t*)navi_array_item(obj->a_policies, idx);
}

navi_uppolicy_squery_t* navi_uppolicy_squery_create()
{
	navi_uppolicy_squery_t* obj = (navi_uppolicy_squery_t*) calloc(1, NVUP_POLICY_SQUERY_OBJ_SZ);

	if (!obj)
		return NULL;

	navi_pool_init(obj->pool, obj, 0x100);
	obj->inkeys.next = obj->inkeys.prev = &obj->inkeys;
	return obj;
}

void navi_uppolicy_squery_destroy(navi_uppolicy_squery_t* obj)
{
	if (obj) {
		if (obj->policy.gr_data)
			json_decref(obj->policy.gr_data);
	}
	navi_pool_destroy(obj->pool);
}

void navi_uppolicy_squery_add_inkey(navi_uppolicy_squery_t* obj, const char* k, const char* v)
{
	nvup_policy_inkey_t* key = (nvup_policy_inkey_t*) navi_pool_calloc(obj->pool, 1,
	    sizeof(nvup_policy_inkey_t));
	key->k = navi_pool_strdup(obj->pool, k);
	if (v)
		key->v = navi_pool_strdup(obj->pool, v);
	else
		key->v = NULL;

	key->link.prev = obj->inkeys.prev;
	key->link.next = &obj->inkeys;
	obj->inkeys.prev->next = &key->link;
	obj->inkeys.prev = &key->link;
}

int navi_uppolicy_squery_resolve(navi_uppolicy_squery_t* obj, const char* upgroup)
{
	navi_upgroup_mgr_t* mgr = navi_upgroup_mgr_instance(NULL);
	if (!mgr)
		return NAVI_INNER_ERR;

	navi_upgroup_t* grp = (navi_upgroup_t*) navi_hash_get_gr(mgr->groups, upgroup);
	if (!grp)
		return NAVI_ARG_ERR;

	return navi_upgroup_policy_query(grp, &obj->inkeys, &obj->policy);
}
