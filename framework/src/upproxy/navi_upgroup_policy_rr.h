/*
 * navi_upgroup_policy_rr.h
 *
 *  Created on: 2013-12-10
 *      Author: li.lei
 */

#ifndef NAVI_UPGROUP_POLICY_RR_H_
#define NAVI_UPGROUP_POLICY_RR_H_
#include "navi_upgroup.h"

NAVI_UPGROUP_POLICY_INIT_FUNC(rr, grp, cfg);
NAVI_UPGROUP_POLICY_RESOLVE_FUNC(rr, grp, req);
NAVI_UPGROUP_POLICY_DESTROY_FUNC(rr, grp);
NAVI_UPSERVER_POLICY_INIT_FUNC(rr, srv, srv_cfg);

#endif /* NAVI_UPGROUP_POLICY_RR_H_ */
