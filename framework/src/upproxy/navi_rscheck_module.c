/*
 * navi_rscheck_module.c
 *
 *  Created on: 2014-02-10
 *      Author: yanguotao@youku.com
 */

#include "navi_module.h"
#include "navi_request.h"
#include "navi_upredis.h"
#include "navi_upserver_redis_rs.h"

static int navi_nrscheck(void *args){
	if (g_rs_servers == NULL || g_rs_servers->hash == NULL){
		return 0;
	}

	uint64_t cur_time =  cur_time_us();
	chain_node_t* nd = g_rs_servers->hash->list_link.next;
	while (nd != &g_rs_servers->hash->list_link) {
		navi_hent_t* e = (navi_hent_t*) ((char*)nd - offsetof(navi_hent_t, list_link));
		navi_upserver_impl_t* srv = (navi_upserver_impl_t*)e->v;
		redis_rs_upserver_data_t* impl = srv->impl_data;
		if (cur_time - impl->last_resolve > impl->resolve_interval*1000000 || 
			srv->upserver->status == NVUP_SRV_UNRESOLVED ||
			(impl->fails.count >= impl->fails.fail_limit && 
				cur_time-impl->fails.first_fail <= (impl->fails.fail_dura+1)*1000000)){
			if (redis_rs_upserver_resolve(srv)){
				impl->fails.count = 0;
				impl->fails.first_fail = 0;
			}
		}
		if (cur_time-impl->fails.first_fail > (impl->fails.fail_dura+1)*1000000){
			impl->fails.count = 0;
			impl->fails.first_fail = 0;
		}

		nd = nd->next;
	}

	return 0;
}

NAVI_MODULE_INIT(nrscheck,module)
{
	module->module_data = NULL;
	/*定时间隔为1s*/
	navi_module_add_interval_timer(module, 1000, navi_nrscheck, NULL, NULL);
	return NAVI_OK;
}

NAVI_MODULE_FREE(nrscheck,module)
{

}

