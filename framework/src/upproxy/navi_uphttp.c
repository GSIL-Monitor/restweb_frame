/*
 * navi_uphttp.c
 *
 *  Created on: 2013-12-11
 *      Author: li.lei
 */

#include "navi_uphttp.h"
#include "navi_upgroup_mgr.h"
#include "navi_inner_util.h"

navi_upreq_proc_t g_nvup_http_proc =
{
	navi_upreq_get_policy_key,
	NULL,
	NULL,
	NULL
};

int navi_request_launch_uphttp_ext(navi_request_t* req, const char* srv_grp, const char* remote_uri, const char *srv_name, const char *host, uint16_t port)
{
	navi_upgroup_mgr_t* mgr = navi_upgroup_mgr_instance(NULL);
	const char* driver_path = mgr->http_driver_path;
	navi_pool_t* pool = navi_request_pool(req);
	navi_upreq_t* obj = navi_pool_calloc(pool, 1, sizeof(navi_upreq_t));

	obj->group_name = navi_pool_strdup(pool, srv_grp);
	if (srv_name != NULL){
		obj->srv_name = navi_pool_strdup(pool, srv_name);
	}
	obj->procs = &g_nvup_http_proc;
	obj->proto = NVUP_PROTO_HTTP;
	obj->out_pack = NULL;

	navi_request_bind_upreq(obj, req);

	if (NAVI_OK != navi_upreq_init(obj)) {
		return NAVI_INNER_ERR;
	}

	navi_upreq_policy_t *policy = &obj->policy;
	if (host != NULL && port > 0){
		inet_pton(AF_INET, host, &(policy->peer_addr_in.sin_addr));
		policy->peer_addr_in.sin_port = htons(port);
		policy->peer_addr_in.sin_family = AF_INET;
	}
	
	char* inner_uri = navi_build_uri(3, driver_path, policy->root_uri,  remote_uri);
	navi_http_request_set_uri(req, inner_uri, 0);
	free(inner_uri);

	navi_hent_t* he;
	void* it;
	if (policy->gr_args) {
		it = navi_hash_iter(policy->gr_args);
		while ((he=navi_hash_iter_next(it))) {
			navi_http_request_set_arg(req, he->k, (const char*)he->v);
		}
		navi_hash_iter_destroy(it);
	}

	if (policy->gr_headers) {
		it = navi_hash_iter(policy->gr_headers);
		while ((he=navi_hash_iter_next(it))) {
			navi_http_request_set_header(req, he->k, (const char*)he->v);
		}
		navi_hash_iter_destroy(it);
	}
	return NAVI_OK;
}

int navi_request_launch_uphttp(navi_request_t* req, const char* srv_grp, const char* remote_uri)
{
	navi_upgroup_mgr_t* mgr = navi_upgroup_mgr_instance(NULL);
	const char* driver_path = mgr->http_driver_path;
	navi_pool_t* pool = navi_request_pool(req);
	navi_upreq_t* obj = navi_pool_calloc(pool, 1, sizeof(navi_upreq_t));

	obj->group_name = navi_pool_strdup(pool, srv_grp);
	obj->procs = &g_nvup_http_proc;
	obj->proto = NVUP_PROTO_HTTP;
	obj->out_pack = NULL;

	navi_request_bind_upreq(obj, req);

	if (NAVI_OK != navi_upreq_init(obj)) {
		return NAVI_INNER_ERR;
	}

	navi_upreq_policy_t *policy = &obj->policy;
	char* inner_uri = navi_build_uri(3, driver_path, policy->root_uri,  remote_uri);
	navi_http_request_set_uri(req, inner_uri, 0);
	free(inner_uri);

	navi_hent_t* he;
	void* it;
	if (policy->gr_args) {
		it = navi_hash_iter(policy->gr_args);
		while ((he=navi_hash_iter_next(it))) {
			navi_http_request_set_arg(req, he->k, (const char*)he->v);
		}
		navi_hash_iter_destroy(it);
	}

	if (policy->gr_headers) {
		it = navi_hash_iter(policy->gr_headers);
		while ((he=navi_hash_iter_next(it))) {
			navi_http_request_set_header(req, he->k, (const char*)he->v);
		}
		navi_hash_iter_destroy(it);
	}
	return NAVI_OK;
}

/*
*cnn_timeout_ms���õ����ӳ�ʱʱ�䣬������ֵ<=0�������ô���
*rw_timeout_ms���õĶ�д��ʱʱ�䣬������ֵ<=0�������ô���
*srv_nameָ����server name��Ϊnullʱ��ָ������ֵ�����ݲ���ѡ��
* host, port����ѡ����ɺ�ָ������http��host��port����hostΪNULL��port<=0ʱ��ָ����ֵ
*/
int navi_request_launch_uphttp_tm(navi_request_t* req, const char* srv_grp, const char* remote_uri, 
	int cnn_timeout_ms, int rw_timeout_ms,  const char *srv_name, const char *host, uint16_t port)
{
	navi_upgroup_mgr_t* mgr = navi_upgroup_mgr_instance(NULL);
	const char* driver_path = mgr->http_driver_path;
	navi_pool_t* pool = navi_request_pool(req);
	navi_upreq_t* obj = navi_pool_calloc(pool, 1, sizeof(navi_upreq_t));

	obj->group_name = navi_pool_strdup(pool, srv_grp);
	if (srv_name != NULL){
		obj->srv_name = navi_pool_strdup(pool, srv_name);
	}
	obj->procs = &g_nvup_http_proc;
	obj->proto = NVUP_PROTO_HTTP;
	obj->out_pack = NULL;

	navi_request_bind_upreq(obj, req);

	if (NAVI_OK != navi_upreq_init(obj)) {
		return NAVI_INNER_ERR;
	}

	navi_upreq_policy_t *policy = &obj->policy;
	if(cnn_timeout_ms > 0){
		policy->cnn_timeout_ms = cnn_timeout_ms;
	}
	if(rw_timeout_ms > 0){
		policy->rw_timeout_ms = rw_timeout_ms;
	}
	
	if (host != NULL && port > 0){
		inet_pton(AF_INET, host, &(policy->peer_addr_in.sin_addr));
		policy->peer_addr_in.sin_port = htons(port);
		policy->peer_addr_in.sin_family = AF_INET;
	}
	
	char* inner_uri = navi_build_uri(3, driver_path, policy->root_uri,  remote_uri);
	navi_http_request_set_uri(req, inner_uri, 0);
	free(inner_uri);

	navi_hent_t* he;
	void* it;
	if (policy->gr_args) {
		it = navi_hash_iter(policy->gr_args);
		while ((he=navi_hash_iter_next(it))) {
			navi_http_request_set_arg(req, he->k, (const char*)he->v);
		}
		navi_hash_iter_destroy(it);
	}

	if (policy->gr_headers) {
		it = navi_hash_iter(policy->gr_headers);
		while ((he=navi_hash_iter_next(it))) {
			navi_http_request_set_header(req, he->k, (const char*)he->v);
		}
		navi_hash_iter_destroy(it);
	}
	return NAVI_OK;
}
