/*
 * navi_upgroup_policy_rest.h
 *
 *  Created on: 2014-08-20
 *      Author: yanguotao@youku.com
 */

#ifndef NAVI_UPGROUP_POLICY_REST_H_
#define NAVI_UPGROUP_POLICY_REST_H_
#include "navi_upgroup.h"

NAVI_UPGROUP_POLICY_INIT_FUNC(rest, grp, cfg);
NAVI_UPGROUP_POLICY_RESOLVE_FUNC(rest, grp, req);
NAVI_UPGROUP_POLICY_DESTROY_FUNC(rest, grp);
NAVI_UPSERVER_POLICY_INIT_FUNC(rest, srv, srv_cfg);

#endif /* NAVI_UPGROUP_POLICY_REST_H_ */
