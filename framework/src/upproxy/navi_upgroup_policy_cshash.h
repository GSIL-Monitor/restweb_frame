/*
 * navi_upgroup_policy_chash.h
 *
 *  Created on: 2014-01-20
 *      Author: yanguotao@youku.com
 */

#ifndef NAVI_UPGROUP_POLICY_CSHASH_H_
#define NAVI_UPGROUP_POLICY_CSHASH_H_
#include "navi_upgroup.h"

NAVI_UPGROUP_POLICY_INIT_FUNC(cshash, grp, cfg);
NAVI_UPGROUP_POLICY_RESOLVE_FUNC(cshash, grp, req);
NAVI_UPGROUP_POLICY_DESTROY_FUNC(cshash, grp);
NAVI_UPSERVER_POLICY_INIT_FUNC(cshash, srv, srv_cfg);

#endif /* NAVI_UPGROUP_POLICY_CSHASH_H_ */
