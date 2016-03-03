/*
 * test_group_mgr.c
 *
 *  Created on: 2014-1-16
 *      Author: li.lei
 */
#include "navi_upgroup_mgr.h"


int main(int argc,char* argv[])
{
	navi_upgroup_mgr_instance("./upgroups");
	navi_upgroup_mgr_instance_destroy();
}
