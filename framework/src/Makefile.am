lib_LTLIBRARIES= libcnavi.la libcnavidriver.la libcnavipolicy.la libnrscheck.la  libcnaviutil.la

libcnavi_la_SOURCES=\
	${top_srcdir}/include/cnavi/navi_bsession.h\
	${top_srcdir}/include/cnavi/navi_common_define.h\
	${top_srcdir}/include/cnavi/navi_formdata_post.h\
	${top_srcdir}/include/cnavi/navi_log.h\
	${top_srcdir}/include/cnavi/navi_simple_array.h\
	${top_srcdir}/include/cnavi/navi_pool.h\
	${top_srcdir}/include/cnavi/navi_simple_hash.h\
	${top_srcdir}/include/cnavi/navi_buf_chain.h\
	${top_srcdir}/include/cnavi/navi_request.h\
	${top_srcdir}/include/cnavi/navi_module.h\
	${top_srcdir}/include/cnavi/navi_gr_iter.h\
	${top_srcdir}/include/cnavi/navi_timer_mgr.h\
	${top_srcdir}/include/cnavi/navi_req_trace.h\
	${top_srcdir}/include/cnavi/navi_response.h\
	${top_srcdir}/include/cnavi/navi_list.h\
	${top_srcdir}/include/cnavi/nnavi_inner_util.h\
	${top_srcdir}/include/cnaviproxy/navi_upserver.h\
	${top_srcdir}/include/cnaviproxy/navi_upgroup_mgr.h\
	${top_srcdir}/include/cnaviproxy/navi_upredis.h\
	${top_srcdir}/include/cnaviproxy/navi_upnavi.h\
	${top_srcdir}/include/cnaviproxy/navi_upreq.h\
	${top_srcdir}/include/cnaviproxy/navi_upreq_inbuf.h\
	${top_srcdir}/include/cnaviproxy/navi_upgroup.h\
	${top_srcdir}/include/cnaviproxy/navi_uphttp.h\
	${top_srcdir}/include/cnaviproxy/navi_uppolicy_query.h\
	${top_srcdir}/include/cnaviproxy/navi_redis_notify.h\
	${top_srcdir}/include/cnaviproxy/navi_pipe.h\
	${top_srcdir}/include/cnaviproxy/navi_vevent_mgr.h\
	${top_srcdir}/include/cnaviproxy/navi_upproto_redis.h\
	${top_srcdir}/include/cnavitask/navi_task.h\
	${top_srcdir}/include/cnavitask/navi_async_conn.h\
	${top_srcdir}/include/cnavitask/navi_bg_job.h\
	${top_srcdir}/include/cnavitask/nvcli_common.h\
	${top_srcdir}/include/cnavitask/navi_task_mgr.h\
	${top_srcdir}/include/cnavitask/navi_grcli.h\
	${top_srcdir}/include/cnavitask/nvcli_http.h\
	${top_srcdir}/include/cnavitask/nvcli_redis.h\
	${top_srcdir}/include/cnaviutil/navi_static_content.h\
	${top_srcdir}/include/cnaviutil/navi_local_redis_resolve.h\
	navi_buf_chain.c\
	navi_bsession.c\
	navi_frame_log.c\
	navi_frame_log.h\
	navi_formdata_post.c\
	navi_gr_iter.c\
	navi_inner_util.c\
	navi_log.c\
	navi_module.c\
	navi_pool.c\
	navi_req_trace.c\
	navi_request.c\
	navi_request_common.c\
	navi_response.c\
	navi_simple_array.c\
	navi_simple_hash.c\
	navi_timer_mgr.c\
	upproxy/navi_pipe.c\
	upproxy/navi_redis_notify.c\
	upproxy/navi_upgroup.c\
	upproxy/navi_upgroup_mgr.c\
	upproxy/navi_uphttp.c\
	upproxy/navi_upnavi.c\
	upproxy/navi_up_network.c\
	upproxy/navi_up_network.h\
	upproxy/navi_uppolicy_query.c\
	upproxy/navi_upproto_redis.c\
	upproxy/navi_upredis.c\
	upproxy/navi_upredis_gr_cmd.c\
	upproxy/navi_upredis_hash_cmd.c\
	upproxy/navi_upredis_list_cmd.c\
	upproxy/navi_upredis_lsh_cmd.c\
	upproxy/navi_upredis_set_cmd.c\
	upproxy/navi_upredis_string_cmd.c\
	upproxy/navi_upredis_zset_cmd.c\
	upproxy/navi_upreq.c\
	upproxy/navi_upreq_inbuf.c\
	upproxy/navi_upserver.c\
	upproxy/navi_upserver_redis_rs.c\
	upproxy/navi_upserver_redis_rs.h\
	upproxy/navi_upserver_single.c\
	upproxy/navi_upserver_single.h\
	upproxy/navi_upserver_local.c\
	upproxy/navi_upserver_local.h\
	upproxy/navi_vevent_mgr.c\
	upproxy/navi_upgroup_policy_rest.c\
	upproxy/navi_upgroup_policy_rest.h\
	task/navi_async_conn.c\
	task/navi_bg_job.c\
	task/navi_grcli.c\
	task/navi_task.c\
	task/navi_task_impl.h\
	task/navi_task_mgr.c\
	task/nvcli_http.c\
	task/nvcli_redis.c\
	util/navi_static_content.c\
	util/exec_util.c\
	util/file_monitor.c\
	util/navi_local_redis_resolve.c\
	#end

libcnavi_la_LIBADD= @jansson_LIBS@ -ldl -lpthread
libcnavi_la_CPPFLAGS = -I${top_srcdir}/include/cnavi\
					   -I${top_srcdir}/include/cnavidriver\
					   -I${top_srcdir}/include/cnaviproxy\
					   -I${top_srcdir}/include/cnavitask\
					   -I${top_srcdir}/include/cnaviutil\
					   @jansson_CFLAGS@
libcnavi_la_LDFLAGS=-version-info @LIBCNAVI_VERSION@


libcnavidriver_la_SOURCES=\
	${top_srcdir}/include/cnavidriver/navi_module_mgr.h\
	${top_srcdir}/include/cnavidriver/navi_module_driver.h\
	${top_srcdir}/include/cnavidriver/navi_request_driver.h\
	navi_module_impl.h\
	navi_module_impl.c\
	navi_request_impl.h\
	navi_request_impl.c\
	navi_module_mgr.c\
	#end

libcnavidriver_la_LIBADD= @jansson_LIBS@ libcnavi.la -ldl
libcnavidriver_la_CPPFLAGS = -I${top_srcdir}/include/cnavi\
							 -I${top_srcdir}/include/cnavidriver @jansson_CFLAGS@\
					   -I${top_srcdir}/include/cnaviproxy\
					   -I${top_srcdir}/include/cnavitask\
					   -I${top_srcdir}/include/cnaviutil

libcnavidriver_la_LDFLAGS=-version-info @LIBCNAVI_VERSION@

libcnavipolicy_la_SOURCES=\
	upproxy/navi_upgroup_policy_rr.c\
	upproxy/navi_upgroup_policy_rr.h\
	upproxy/navi_upgroup_policy_cshash.c\
	upproxy/navi_upgroup_policy_cshash.h\
	upproxy/md5.c\
	upproxy/md5.h\
	#end

libcnavipolicy_la_LIBADD= @jansson_LIBS@ libcnavi.la -ldl -lm
libcnavipolicy_la_CPPFLAGS = -I${top_srcdir}/include/cnavi\
							 -I${top_srcdir}/include/cnaviproxy @jansson_CFLAGS@
libcnavipolicy_la_LDFLAGS=-version-info @LIBCNAVI_VERSION@

libnrscheck_la_SOURCES=\
	upproxy/navi_rscheck_module.c\
	#end

libnrscheck_la_LIBADD= @jansson_LIBS@ libcnavi.la -ldl
libnrscheck_la_CPPFLAGS = -I${top_srcdir}/include/cnavi\
							 -I${top_srcdir}/include/cnaviproxy @jansson_CFLAGS@
libnrscheck_la_LDFLAGS=-version-info @LIBCNAVI_VERSION@

libcnaviutil_la_SOURCES=\
	${top_srcdir}/include/cnaviutil/curl_cli.h\
	util/buffer_util.h\
	util/buffer_util.c\
	util/curl_cli.c\
	#end

libcnaviutil_la_LIBADD= @libcurl_LIBS@ libcnavi.la -ldl
libcnaviutil_la_CPPFLAGS = -I${top_srcdir}/include/cnaviutil\
			   -I${top_srcdir}/include/cnavi\
					   @libcurl_CFLAGS@
libcnaviutil_la_LDFLAGS=-version-info @LIBCNAVI_VERSION@

