noinst_PROGRAMS = test_timer_mgr test_pool test_hash test_request test_util test_module_mgr\
				  test_request_drive test_array test_upredis_proto test_group_mgr test_buf_chain
lib_LTLIBRARIES = libtest_app1.la libtest_app2.la libtest_prev1.la libtest_prev2.la libtest_post1.la libtest_post2.la\
				  libtest_redis_proxy.la libtest_http_proxy.la libtest_navi_proxy.la libtest_alldrive.la

test_timer_mgr_SOURCES = test_timer_mgr.c
test_timer_mgr_LDADD = ../src/.libs/libcnavi.la
test_timer_mgr_CPPFLAGS =  -I../include/cnavi -I../include/cnavidriver -I../src

test_pool_SOURCES = test_pool.c
test_pool_LDADD = ../src/.libs/libcnavi.la
test_pool_CPPFLAGS =  -I../include/cnavi -I../include/cnavidriver -I../src

test_buf_chain_SOURCES = test_buf_chain.c
test_buf_chain_LDADD = ../src/.libs/libcnavi.la  ../src/.libs/libcnavidriver.la
test_buf_chain_CPPFLAGS =  -I../include/cnavi -I../include/cnavidriver -I../src

test_hash_SOURCES = test_hash.c
test_hash_LDADD = ../src/.libs/libcnavi.la
test_hash_CPPFLAGS =  -I../include/cnavi -I../include/cnavidriver -I../src

test_array_SOURCES = test_array.c
test_array_LDADD = ../src/.libs/libcnavi.la
test_array_CPPFLAGS =  -I../include/cnavi -I../include/cnavidriver -I../src

test_request_SOURCES = test_request.c
test_request_LDADD = ../src/.libs/libcnavi.la ../src/.libs/libcnavidriver.la
test_request_CPPFLAGS = -I../include/cnavi -I../include/cnavidriver -I../

test_util_SOURCES = test_util.c
test_util_LDADD = ../src/.libs/libcnavi.la ../src/.libs/libcnavidriver.la 
test_util_CPPFLAGS = -I../include/cnavi -I../include/cnavidriver -I../src

test_module_mgr_SOURCES = test_module_mgr.c
test_module_mgr_LDADD = ../src/.libs/libcnavi.la ../src/.libs/libcnavidriver.la 
test_module_mgr_CPPFLAGS = -I../include/cnavi -I../include/cnavidriver -I../src

test_request_drive_SOURCES = test_request_drive.c
test_request_drive_LDADD = ../src/.libs/libcnavi.la ../src/.libs/libcnavidriver.la 
test_request_drive_CPPFLAGS = -I../include/cnavi -I../include/cnavidriver -I../src

test_upredis_proto_SOURCES = test_upredis_proto.c
test_upredis_proto_LDADD = ../src/.libs/libcnavi.la
test_upredis_proto_CPPFLAGS = -I../include/cnavi -I../include/cnaviproxy -I../src

test_group_mgr_SOURCES = test_group_mgr.c
test_group_mgr_LDADD = ../src/.libs/libcnavi.la
test_group_mgr_CPPFLAGS = -I../include/cnavi -I../include/cnaviproxy -I../src



libtest_app1_la_SOURCES = test_app1_module.c
libtest_app1_la_LIBADD = ../src/.libs/libcnavi.la
libtest_app1_la_CPPFLAGS =  -I../include/cnavi -I../include/cnavidriver -I../src

libtest_app2_la_SOURCES = test_app2_module.c
libtest_app2_la_LIBADD = ../src/.libs/libcnavi.la
libtest_app2_la_CPPFLAGS =  -I../include/cnavi -I../include/cnavidriver -I../src

libtest_prev1_la_SOURCES = test_prev1_module.c
libtest_prev1_la_LIBADD = ../src/.libs/libcnavi.la
libtest_prev1_la_CPPFLAGS =  -I../include/cnavi -I../include/cnavidriver -I../src

libtest_prev2_la_SOURCES = test_prev2_module.c
libtest_prev2_la_LIBADD = ../src/.libs/libcnavi.la
libtest_prev2_la_CPPFLAGS =  -I../include/cnavi -I../include/cnavidriver -I../src

libtest_post1_la_SOURCES = test_post1_module.c
libtest_post1_la_LIBADD = ../src/.libs/libcnavi.la
libtest_post1_la_CPPFLAGS =  -I../include/cnavi -I../include/cnavidriver -I../src

libtest_post2_la_SOURCES = test_post2_module.c
libtest_post2_la_LIBADD = ../src/.libs/libcnavi.la
libtest_post2_la_CPPFLAGS =  -I../include/cnavi -I../include/cnavidriver -I../src

libtest_redis_proxy_la_SOURCES = test_redis_proxy_module.c
libtest_redis_proxy_la_LIBADD = ../src/.libs/libcnavi.la
libtest_redis_proxy_la_CPPFLAGS =  -I../include/cnavi -I../include/cnavidriver -I../include/cnaviproxy -I../src

libtest_http_proxy_la_SOURCES = test_http_proxy_module.c
libtest_http_proxy_la_LIBADD = ../src/.libs/libcnavi.la
libtest_http_proxy_la_CPPFLAGS =  -I../include/cnavi -I../include/cnavidriver -I../include/cnaviproxy -I../src

libtest_navi_proxy_la_SOURCES = test_navi_proxy_module.c
libtest_navi_proxy_la_LIBADD = ../src/.libs/libcnavi.la
libtest_navi_proxy_la_CPPFLAGS =  -I../include/cnavi -I../include/cnavidriver -I../include/cnaviproxy -I../src

libtest_alldrive_la_SOURCES = test_alldrive_module.c
libtest_alldrive_la_LIBADD = ../src/.libs/libcnavi.la
libtest_alldrive_la_CPPFLAGS =  -I../include/cnavi -I../include/cnavidriver -I../include/cnaviproxy -I../include/cnaviutil \
								-I../include/cnavitask -I../src

