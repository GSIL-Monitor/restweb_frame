/*
 * navi_upproto_redis.c
 *
 *  Created on: 2013-12-12
 *      Author: li.lei
 */
#include "navi_upproto_redis.h"

navi_upreq_parse_status_e nvup_redis_proto_parse_in(nvup_redis_proto_t* ctx, uint8_t* in, size_t sz)
{
	int ch_i;
	u_char ch;
	nvup_inbuf_t* buf = &ctx->parse_buf;
	nvup_inbuf_fillin(buf, in, sz);

	while ((ch_i = nvup_inbuf_probe(buf)) != -1) {
		ch = ch_i;
		switch (ctx->pending_stage) {
		case redis_stage_done:
			ctx->proto_type = redis_type_proto_error;
			break;
		case redis_stage_start:
			switch (ch) {
			case ':':
				ctx->proto_type = redis_type_num;
				ctx->pending_stage = redis_stage_number_line;
				break;
			case '-':
				ctx->proto_type = redis_type_error_reply;
				ctx->pending_stage = redis_stage_single_line;
				break;
			case '+':
				ctx->proto_type = redis_type_status_reply;
				ctx->pending_stage = redis_stage_single_line;
				break;
			case '$':
				ctx->proto_type = redis_type_single_bulk;
				ctx->pending_stage = redis_stage_bulk_len;
				ctx->cur_num_check = 0;
				break;
			case '*':
				ctx->proto_type = redis_type_multi_bulk;
				ctx->pending_stage = redis_stage_bulk_count;
				ctx->cur_num_check = 0;
				break;
			default:
				ctx->proto_type = redis_type_proto_error;
				ctx->pending_stage = redis_stage_done;
				break;
			}
			nvup_inbuf_accept_unit(buf);
			break;
		case redis_stage_single_line:
			switch (ch) {
			case '\r':
				ctx->break_status = redis_break_r;
				break;
			case '\n':
				if (ctx->break_status == redis_break_r) {
					ctx->break_status = redis_break_pending;
					char** ppd = NULL;
					if (ctx->proto_type == redis_type_multi_bulk) {
						redis_bulk_t* bk = navi_array_push(ctx->in_bulks);
						bk->bulk_type = ctx->pending_bulk_type;
						ppd = &bk->s;
						if (--ctx->bulk_count == 0) {
							ctx->pending_stage = redis_stage_done;
							ctx->bulk_count = ctx->in_bulks->count;
						}
						else
							ctx->pending_stage = redis_stage_bulk_start;
					}
					else {
						ctx->pending_stage = redis_stage_done;
						ppd = &ctx->str_result;
					}
					*(buf->cur_probe - 2) = 0;
					*ppd = navi_pool_strdup(ctx->pool, buf->cur_pending);
					nvup_inbuf_accept_unit(buf);
				}
				break;
			default:
				if (ctx->break_status == redis_break_r) {
					ctx->break_status = redis_break_pending;
				}
				break;
			}
			break;

		case redis_stage_bulk_len:
		case redis_stage_bulk_count:
		case redis_stage_number_line:
			switch (ch) {
			case '\r':
				if (ctx->break_status == redis_break_r) {
					ctx->pending_stage = redis_stage_done;
					ctx->break_status = redis_break_pending;
					ctx->proto_type = redis_type_proto_error;
				}
				else
					ctx->break_status = redis_break_r;
				break;
			case '\n':
				if (ctx->break_status == redis_break_r) {
					ctx->break_status = redis_break_pending;

					if (buf->cur_pending + 2 == buf->cur_probe) {
						//¿ÕµÄÊý×ÖÐÐ
						ctx->pending_stage = redis_stage_done;
						ctx->proto_type = redis_type_proto_error;
					}
					else {
						*(buf->cur_probe - 2) = 0;
						if (ctx->pending_stage == redis_stage_number_line) {
							int64_t *ppi;
							if (ctx->proto_type == redis_type_multi_bulk) {
								redis_bulk_t* bk = navi_array_push(ctx->in_bulks);
								bk->bulk_type = ctx->pending_bulk_type;
								ppi = &bk->i;
								if (--ctx->bulk_count == 0) {
									ctx->pending_stage = redis_stage_done;
									ctx->bulk_count = ctx->in_bulks->count;
								}
								else
									ctx->pending_stage = redis_stage_bulk_start;
							}
							else {
								ppi = &ctx->num_result;
								ctx->pending_stage = redis_stage_done;
							}
							*ppi = strtoll(buf->cur_pending,NULL,10);
						}
						else if (ctx->pending_stage == redis_stage_bulk_count) {
							ctx->bulk_count = atoi(buf->cur_pending);
							if (ctx->bulk_count == 0) { /*empty mbulk*/
								ctx->pending_stage = redis_stage_done;
								if (ctx->in_bulks == NULL)
									ctx->in_bulks = navi_array_create(ctx->pool, 1,
										sizeof(redis_bulk_t));
							}
							else if (ctx->bulk_count == -1) { /*nil mbulk*/
								ctx->pending_stage = redis_stage_done;
								ctx->in_bulks = NULL;
							}
							else {
								ctx->pending_stage = redis_stage_bulk_start;
								if (ctx->in_bulks == NULL)
									ctx->in_bulks = navi_array_create(ctx->pool, ctx->bulk_count,
										sizeof(redis_bulk_t));
							}
						}
						else if (ctx->pending_stage == redis_stage_bulk_len) {
							ctx->bulk_size = atoi(buf->cur_pending);
							ctx->cur_bulk_check = 0;
							if (ctx->bulk_size <= -1 && ctx->proto_type == redis_type_multi_bulk) {
								redis_bulk_t* bk = navi_array_push(ctx->in_bulks);
								bk->bulk_type = redis_type_single_bulk;
								bk->s = NULL;

								if (--ctx->bulk_count == 0) {
									ctx->pending_stage = redis_stage_done;
									ctx->bulk_count = ctx->in_bulks->count;
								}
								else
									ctx->pending_stage = redis_stage_bulk_start;
							}
							else if (ctx->bulk_size <= -1 && ctx->proto_type == redis_type_single_bulk) {
								ctx->pending_stage = redis_stage_done;
								ctx->bulk_count = 0;
								ctx->in_bulks = NULL;
							}
							else {
								ctx->pending_stage = redis_stage_bulk_content;
								if (ctx->proto_type == redis_type_single_bulk)
									ctx->bulk_count = 1;
							}
						}
					}
				}
				else {
					ctx->pending_stage = redis_stage_done;
					ctx->break_status = redis_break_pending;
					ctx->proto_type = redis_type_proto_error;

				}
				nvup_inbuf_accept_unit(buf);
				break;
			case '-':
				if (ctx->cur_num_check == 0) {
					ctx->cur_num_check++;
				}
				else {
					ctx->pending_stage = redis_stage_done;
					ctx->break_status = redis_break_pending;
					ctx->proto_type = redis_type_proto_error;
					nvup_inbuf_accept_unit(buf);
				}
				break;
			default:
				if (ch < '0' || ch > '9') {
					ctx->pending_stage = redis_stage_done;
					ctx->break_status = redis_break_pending;
					ctx->proto_type = redis_type_proto_error;
					nvup_inbuf_accept_unit(buf);
				}
				else {
					ctx->cur_num_check++;
				}
				break;
			}
			break;
		case redis_stage_bulk_start:
			switch (ch) {
			case ':':
				ctx->pending_stage = redis_stage_number_line;
				ctx->pending_bulk_type = redis_type_num;
				break;
			case '-':
				ctx->pending_stage = redis_stage_single_line;
				ctx->pending_bulk_type = redis_type_error_reply;
				break;
			case '+':
				ctx->pending_stage = redis_stage_single_line;
				ctx->pending_bulk_type = redis_type_status_reply;
				break;
			case '$':
				ctx->pending_stage = redis_stage_bulk_len;
				ctx->pending_bulk_type = redis_type_single_bulk;
				ctx->cur_num_check = 0;
				break;
			default:
				ctx->proto_type = redis_type_proto_error;
				ctx->break_status = redis_break_pending;
				ctx->pending_stage = redis_stage_done;
				break;
			}
			/*
			if (ch != '$') {
				ctx->pending_stage = redis_stage_done;
				ctx->break_status = redis_break_pending;
				ctx->proto_type = redis_type_proto_error;
			}
			else {
				ctx->pending_stage = redis_stage_bulk_len;
				ctx->cur_num_check = 0;
			}*/
			nvup_inbuf_accept_unit(buf);
			break;
		case redis_stage_bulk_content:
			if (ctx->cur_bulk_check == ctx->bulk_size) {
				if (ctx->break_status == redis_break_pending) {
					if (ch != '\r') {
						ctx->pending_stage = redis_stage_done;
						ctx->break_status = redis_break_pending;
						ctx->proto_type = redis_type_proto_error;
						nvup_inbuf_accept_unit(buf);
					}
					else {
						ctx->break_status = redis_break_r;
					}
				}
				else if (ctx->break_status == redis_break_r) {
					ctx->break_status = redis_break_pending;
					if (ch != '\n') {
						ctx->pending_stage = redis_stage_done;
						ctx->proto_type = redis_type_proto_error;
					}
					else {
						*(buf->cur_probe - 2) = 0;

						if (ctx->in_bulks == NULL)
							ctx->in_bulks = navi_array_create(ctx->pool, 1, sizeof(redis_bulk_t));

						redis_bulk_t* bk = navi_array_push(ctx->in_bulks);
						bk->bulk_type = redis_type_single_bulk;
						bk->s = navi_pool_strdup(ctx->pool, buf->cur_pending);

						if (--ctx->bulk_count) {
							ctx->pending_stage = redis_stage_bulk_start;
						}
						else {
							ctx->pending_stage = redis_stage_done;
							ctx->bulk_count = ctx->in_bulks->count;
						}
					}
					nvup_inbuf_accept_unit(buf);
				}
			}
			else
				ctx->cur_bulk_check++;
			break;
		}
		if ( ctx->pending_stage == redis_stage_done )
			break;
	}

	nvup_inbuf_check(buf);
	if (ctx->proto_type == redis_type_proto_error) {
		if (ctx->pending_stage == redis_stage_start)
			return NVUP_PARSE_AGAIN;
		else
			return NVUP_PARSE_PROTO_ERROR;
	}

	if (ctx->pending_stage == redis_stage_done) {
		return NVUP_PARSE_DONE;
	}

	return NVUP_PARSE_AGAIN;
}


#define MBULK_FMT "*%d\r\n"
#define BULK_FMT "$%d\r\n%s\r\n"

typedef struct buf_merge_s
{
	char* pbuf;
	char* p;
	char* end;
} buf_merge_t;

static void merge_output(buf_merge_t* merge, navi_buf_chain_t* out, const char* fmt, ...)
{
	if (fmt == NULL || strlen(fmt) == 0) {
		if (merge->p != merge->pbuf) {
			navi_buf_chain_append(out, merge->pbuf, merge->p - merge->pbuf);
		}
		free(merge->pbuf);
		return;
	}
	size_t sz;
	va_list vl;
	va_start(vl, fmt);
	sz = vsnprintf(merge->p, merge->end - merge->p, fmt, vl);
	if (sz + 1 > merge->end - merge->p) {
		navi_buf_chain_append(out, merge->pbuf, merge->p - merge->pbuf);
		merge->p = merge->pbuf;

		if (sz + 1 > merge->end - merge->p) {
			char* nbuf = (char*) malloc(sz + 1024);
			free(merge->pbuf);
			merge->p = merge->pbuf = nbuf;
			merge->end = merge->p + sz + 1024;
		}
		va_end(vl);
		va_start(vl, fmt);
		sz = vsprintf(merge->p, fmt, vl);
		merge->p += sz;
	}
	else {
		merge->p += sz;
	}

	if (merge->p == merge->end - 1) {
		navi_buf_chain_append(out, merge->pbuf, merge->p - merge->pbuf);
		merge->p = merge->pbuf;
	}
	va_end(vl);
}

void nvup_redis_cmd_2outpack(nvup_redis_cmd_t* cmd, navi_buf_chain_t* out_pack)
{
	size_t bulk_cnt = 1;
	buf_merge_t merge;

	merge.p = merge.pbuf = (char*) malloc(1024);
	merge.end = merge.p + 1024;

	int pt, pt2, i, j;
	navi_array_part_t* part, *part2;
	nvup_redis_cmd_key_t* ka;
	char* arg;

	switch (cmd->cmd_st) {
	case NVUP_REDIS_CMDST_1KEY:
		{
		switch (cmd->s_key->arg_st) {
		case NVUP_REDIS_KEY_0ARG:
			bulk_cnt += 1;
			break;
		case NVUP_REDIS_KEY_1ARG:
			bulk_cnt += 2;
			break;
		case NVUP_REDIS_KEY_2ARG:
			bulk_cnt += 3;
			break;
		case NVUP_REDIS_KEY_MARG:
			bulk_cnt += cmd->s_key->margs->count + 1;
			break;
		}
	}
		break;

	case NVUP_REDIS_CMDST_MKEYS:
		{
		int pt, i;
		for (pt = 0; pt < cmd->m_keys->part_size; pt++) {
			part = cmd->m_keys->parts[pt];
			if (part == NULL)
				break;

			ka = (nvup_redis_cmd_key_t*) part->allocs;
			for (i = 0; i < part->used; i++, ka++) {
				switch (ka->arg_st) {
				case NVUP_REDIS_KEY_0ARG:
					bulk_cnt += 1;
					break;
				case NVUP_REDIS_KEY_1ARG:
					bulk_cnt += 2;
					break;
				case NVUP_REDIS_KEY_2ARG:
					bulk_cnt += 3;
					break;
				case NVUP_REDIS_KEY_MARG:
					bulk_cnt += ka->margs->count + 1;
					break;
				}
			}
		}
	}
		break;

	case NVUP_REDIS_CMDST_PUR_1ARG:
		bulk_cnt += 1;
		break;

	case NVUP_REDIS_CMDST_PUR_MARGS:
		bulk_cnt += cmd->m_args->count;
		break;
	default:
		return;
	}

	merge_output(&merge, out_pack, MBULK_FMT BULK_FMT, bulk_cnt,
	    strlen(cmd->cmd), cmd->cmd);

	switch (cmd->cmd_st) {

	case NVUP_REDIS_CMDST_1KEY:
		{
		switch (cmd->s_key->arg_st) {
		case NVUP_REDIS_KEY_0ARG:
			merge_output(&merge, out_pack, BULK_FMT,
			    strlen(cmd->s_key->key), cmd->s_key->key);
			break;
		case NVUP_REDIS_KEY_1ARG:
			merge_output(&merge, out_pack, BULK_FMT BULK_FMT,
			    strlen(cmd->s_key->key), cmd->s_key->key,
			    strlen(cmd->s_key->arg1), cmd->s_key->arg1);
			break;
		case NVUP_REDIS_KEY_2ARG:
			merge_output(&merge, out_pack, BULK_FMT BULK_FMT BULK_FMT,
			    strlen(cmd->s_key->key), cmd->s_key->key,
			    strlen(cmd->s_key->arg1), cmd->s_key->arg1,
			    strlen(cmd->s_key->arg2), cmd->s_key->arg2);
			break;
		case NVUP_REDIS_KEY_MARG:
			merge_output(&merge, out_pack, BULK_FMT,
			    strlen(cmd->s_key->key), cmd->s_key->key);
			for (pt = 0; pt < cmd->s_key->margs->part_size; pt++) {
				part = cmd->s_key->margs->parts[pt];
				if (!part)
					break;

				char** pa = (char**) part->allocs;
				for (i = 0; i < part->used; i++, pa++) {
					merge_output(&merge, out_pack, BULK_FMT, strlen(*pa), *pa);
				}
			}
			break;
		}
		merge_output(&merge, out_pack, NULL);
		return;
	}

	case NVUP_REDIS_CMDST_MKEYS:
		{
		int pt, i;
		for (pt = 0; pt < cmd->m_keys->part_size; pt++) {
			part = cmd->m_keys->parts[pt];
			if (part == NULL)
				break;

			ka = (nvup_redis_cmd_key_t*) part->allocs;
			for (i = 0; i < part->used; i++, ka++) {
				merge_output(&merge, out_pack, BULK_FMT,
				    strlen(ka->key), ka->key);
				switch (ka->arg_st) {
				case NVUP_REDIS_KEY_1ARG:
					merge_output(&merge, out_pack, BULK_FMT,
					    strlen(ka->arg1), ka->arg1);
					break;
				case NVUP_REDIS_KEY_2ARG:
					merge_output(&merge, out_pack, BULK_FMT BULK_FMT,
					    strlen(ka->arg1), ka->arg1, strlen(ka->arg2), ka->arg2);
					break;
				case NVUP_REDIS_KEY_MARG:
					for (pt2 = 0; pt2 < ka->margs->part_size; pt2++) {
						part2 = ka->margs->parts[pt2];
						if (!part2)
							break;

						char** pa = (char**) part2->allocs;
						for (j = 0; j < part2->used; j++, pa++) {
							merge_output(&merge, out_pack, BULK_FMT, strlen(*pa), *pa);
						}
					}
					break;
				}
			}
		}
		merge_output(&merge, out_pack, NULL);
		return;
	}

	case NVUP_REDIS_CMDST_PUR_1ARG:
		merge_output(&merge, out_pack, BULK_FMT, strlen(cmd->s_arg), cmd->s_arg);
		merge_output(&merge, out_pack, NULL);
		return;
	case NVUP_REDIS_CMDST_PUR_MARGS:
		{
		for (pt = 0; pt < cmd->m_args->part_size; pt++) {
			part = cmd->m_args->parts[pt];
			if (!part)
				break;
			char** pa = (char**) part->allocs;
			for (i = 0; i < part->used; i++, pa++) {
				merge_output(&merge, out_pack, BULK_FMT, strlen(*pa), *pa);
			}
		}
		merge_output(&merge, out_pack, NULL);
		return;
	}

	default:
		return;
	} //end out swith
}
