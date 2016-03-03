/*
 * test_module_mgr.c
 *
 *  Created on: 2013-9-23
 *      Author: li.lei
 */

#include "navi_module_mgr.h"

int main() {
	navi_module_mgr_t* mgr = navi_mgr_init("./conf/");


	sleep(2);
	printf("=============touch test_app1.json================\n");
	system("touch ./conf/test_app1.json");
	navi_mgr_check_modules(mgr);

	sleep(2);
	printf("=============touch navi.json================\n");
	system("touch ./conf/navi.json");
	navi_mgr_check_modules(mgr);

	sleep(1);
	printf("=============delete test_app2.json================\n");
	system("mv ./conf/test_app2.json ./conf/test_app2.json.mv");
	navi_mgr_check_modules(mgr);

	sleep(1);
	printf("=============add test_app2.json================\n");
	system("mv ./conf/test_app2.json.mv ./conf/test_app2.json");
	navi_mgr_check_modules(mgr);

	sleep(1);
	printf("=============rename test_app2.json================\n");
	system("mv ./conf/test_app2.json ./conf/test_app2new.json");
	navi_mgr_check_modules(mgr);

	system("mv ./conf/test_app2new.json ./conf/test_app2.json");

	navi_mgr_free(mgr);
}
