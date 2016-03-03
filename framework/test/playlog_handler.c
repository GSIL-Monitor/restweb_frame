#include "playlog_handler.h"
#include "ntask_test_log.h"


char * playlog_report_cmd_sha = NULL;
char * playlog_getlru_cmd_sha = NULL;

static const char * playlog_report_cmd = "local err_msg = {}\r\n\
                                 local arg_sz = table.maxn(ARGV)\r\n\
                                 if arg_sz < 1 then\r\n\
                             	     err_msg[\"err\"] = \"bad notify param\"\r\n\
                             	     return err_msg\r\n\
                                 end\r\n\
                                 redis.call('rpush','templog',arg_sz)\r\n\
                                 local current_slot = redis.call('get', 'playlog_cur_slot')\r\n\
                                 if not current_slot or tonumber(current_slot) >= 1000000000 then\r\n\
                                     current_slot = 1\r\n\
                                     redis.call('set', 'playlog_cur_slot', current_slot)\r\n\
                                 end\r\n\
                                 local current_slot_key = string.format(\"playlog::%09d\", current_slot)\r\n\
                                 local current_slot_key_exist = redis.call('exists', current_slot_key)\r\n\
                                 local i = 1\r\n\
                                 while i <= arg_sz - 1 do\r\n\
                                     local zistr = string.format(\"zincrby %s %s %s\",current_slot_key,ARGV[i+1],ARGV[i])\r\n\
                                     redis.call('rpush','templog',zistr)\r\n\
                                     local zires = redis.call('zincrby', current_slot_key, tonumber(ARGV[i+1]),ARGV[i])\r\n\
                                     if not zires then\r\n\
                                         err_msg[\"err\"] = \"zincrby failed\"\r\n\
                                         return err_msg\r\n\
                                     end\r\n\
                                     i = i + 2\r\n\
                                 end\r\n\
                                 redis.call('rpush','templog',current_slot_key_exist)\r\n\
                                 if current_slot_key_exist == 0 then\r\n\
                                     redis.call('expire',current_slot_key,3600)\r\n\
                                     redis.call('rpush','templog','expire current_slot_key')\r\n\
                                 end\r\n\
                                 err_msg[\"ok\"] =\"ok\"\r\n\
                                 return err_msg";
                                
static const char * playlog_getlru_cmd = "local err_msg = {}\r\n\
                                 local arg_sz = table.maxn(ARGV)\r\n\
                                 if arg_sz < 1 then\r\n\
                             	     err_msg[\"err\"] = \"bad notify param\"\r\n\
                             	     return err_msg\r\n\
                                 end\r\n\
                                 local result = {}\r\n\
                                 local current_slot = redis.call('get', 'playlog_cur_slot')\r\n\
                                 if not current_slot then\r\n\
                                     return result\r\n\
                                 end\r\n\
                                 local current_slot_key = string.format(\"playlog::%09d\", current_slot)\r\n\
                                 local total_num = redis.call('scard','all_file_set')\r\n\
                                 local play_num = redis.call('zcard',current_slot_key)\r\n\
                                 local rem_num = tonumber(ARGV[1])\r\n\
                                 local keep_num = tonumber(total_num) - rem_num\r\n\
                                 local log = string.format(\"total_num:%d,play_num:%d,rem_num:%d\", total_num, play_num, rem_num)\r\n\
                                 redis.call('rpush','templog',log)\r\n\
                                 local lrures\r\n\
                                 redis.call('del','temp_file_set')\r\n\
                                 if play_num >= keep_num then\r\n\
                                     local temprs = redis.call('zrevrangebyscore', current_slot_key, '+inf', '-inf', 'limit', 0, keep_num)\r\n\
                                     if temprs ~= nil and table.maxn(temprs) > 0 then\r\n\
                                         for i, v in ipairs(temprs) do\r\n\
                                             redis.call('sadd','temp_file_set',v)\r\n\
                                         end\r\n\
                                     end\r\n\
                                     local temp_file_set_sz = redis.call('scard','temp_file_set')\r\n\
                                     redis.call('rpush','templog','temp_file_set_sz='..temp_file_set_sz)\r\n\
                                     lrures = redis.call('sdiff','all_file_set','temp_file_set')\r\n\
                                 else\r\n\
                                     local temprs = redis.call('zrange', current_slot_key, '0', '-1')\r\n\
                                     if temprs ~= nil and table.maxn(temprs) > 0 then\r\n\
                                         for i, v in ipairs(temprs) do\r\n\
                                             redis.call('sadd','temp_file_set',v)\r\n\
                                         end\r\n\
                                     end\r\n\
                                     lrures = redis.call('sdiff','all_file_set','temp_file_set')\r\n\
                                 end\r\n\
                                 local n = 0\r\n\
                                 if lrures ~= nil and table.maxn(lrures) > 0 then\r\n\
                                     for i, v in ipairs(lrures) do\r\n\
                                         if n == rem_num then\r\n\
                                             break\r\n\
                                         end\r\n\
                                         table.insert(result, v)\r\n\
                                         n = n+1\r\n\
                                     end\r\n\
                                 end\r\n\
                                 return result";


static navi_upredis_script_t * build_script(navi_pool_t* pool, navi_array_t* query_list)
{
	playlog_t* record = NULL;
	navi_upredis_script_t * script = navi_pool_calloc(pool, 1, sizeof(navi_upredis_script_t));
	if (script == NULL)
		return NULL;
	
    script->args_sz = 2*query_list->count;
    script->args = (char**)navi_pool_calloc(pool, script->args_sz, sizeof(char*));
    if(script->args == NULL)
        return NULL;

    int i = 0;
    for(; i < query_list->count; ++i)
    {
    	record = (playlog_t*)navi_array_item(query_list, i);
        script->args[2*i] = record->fileid;
        script->args[2*i+1] = record->count;
    }
    return script;
}                                

void playlog_report_sha_result_proc(void* parent, nvcli_redis_t* ss, const navi_upreq_result_t* result)
{
	ntask_test_log(NAVI_LOG_DEBUG,"playlog init sha result:\n%s", json_dumps(result->js, JSON_PRESERVE_ORDER));

	if (playlog_report_cmd_sha != NULL) {
		free(playlog_report_cmd_sha);
        playlog_report_cmd_sha = NULL;
	}
	playlog_report_cmd_sha = strdup(result->s);
}

void playlog_getlru_sha_result_proc(void* parent, nvcli_redis_t* ss, const navi_upreq_result_t* result)
{
	ntask_test_log(NAVI_LOG_DEBUG,"playlog init sha result:\n%s", json_dumps(result->js, JSON_PRESERVE_ORDER));

	if (playlog_getlru_cmd_sha != NULL) {
		free(playlog_getlru_cmd_sha);
        playlog_getlru_cmd_sha = NULL;
	}
	playlog_getlru_cmd_sha = strdup(result->s);
}


void playlog_sha_error_proc(void* parent, nvcli_redis_t* ss, nvcli_error_e e)
{
	ntask_test_log(NAVI_LOG_WARNING,"playlog init error");
}

int playlog_init(navi_task_t* task, const struct sockaddr* peer_addr)
{
    nvcli_redis_t *redis = nvtask_new_redis_session(task,peer_addr,playlog_report_sha_result_proc, playlog_sha_error_proc,200, 100000, 100000);
	if (redis == NULL) 
        return -1;
	nvcli_redis_lua_load(redis,playlog_report_cmd);
    nvcli_redis_t *redis2 = nvtask_new_redis_session(task,peer_addr,playlog_getlru_sha_result_proc, playlog_sha_error_proc,200, 100000, 100000);
	if (redis2 == NULL) 
        return -1;
    nvcli_redis_lua_load(redis2,playlog_getlru_cmd);
    return 0;
}

int playlog_report(nvcli_redis_t* redis, navi_pool_t* pool, navi_array_t *playlog_list)
{
	navi_upredis_script_t* script = build_script(pool,playlog_list);
	if (script == NULL)
		return -1;
	
	if (playlog_report_cmd_sha != NULL) {
		script->script_sha = playlog_report_cmd_sha;
		nvcli_redis_lua_evalsha(redis,"aaa",script,redisproto_get_ok_result_from_status);
	}
	else {
		script->script = playlog_report_cmd;
		nvcli_redis_lua_eval(redis,"aaa",script,redisproto_get_ok_result_from_status);
	}
	return 0;
}

int playlog_lru_get(nvcli_redis_t* redis, unsigned int maxn, navi_pool_t* pool)
{
	if (maxn > 1000000)
		return -1;
	char *limitnum = (char*)navi_pool_alloc(pool,8);
    if (limitnum == NULL)
		return -2;
	snprintf(limitnum,8,"%d",maxn);
    navi_upredis_script_t * script = navi_pool_calloc(pool, 1, sizeof(navi_upredis_script_t));
	if (script == NULL)
		return -3;
    script->args_sz = 1;
    script->args = (char**)navi_pool_calloc(pool, script->args_sz, sizeof(char*));
    if(script->args == NULL)
        return -4;
    *script->args = limitnum;
    
	if (playlog_getlru_cmd_sha!= NULL) {
		script->script_sha = playlog_getlru_cmd_sha;
		nvcli_redis_lua_evalsha(redis,"aaa",script,redisproto_get_strs_from_mbulk);
	}
	else {
		script->script = playlog_getlru_cmd;
		nvcli_redis_lua_eval(redis,"aaa",script,redisproto_get_strs_from_mbulk);
	}
	return 0;
}

int playlog_lru_update(nvcli_redis_t* redis)
{
	return nvcli_redis_incrby(redis,"playlog_cur_slot",1);
}

