/*
 * navi_formdata_post.c
 *
 *  Created on: 2015Äê6ÔÂ28ÈÕ
 *      Author: L-F000000-PC
 */

#include "navi_formdata_post.h"

navi_formdata_t* navi_formdata_create()
{
	navi_formdata_t* obj = (navi_formdata_t*)calloc(1, sizeof(navi_formdata_t)+0x1000);
	navi_pool_init(obj->pool,obj,0x1000);
	char buf[40];
	char* p = buf;
	p += snprintf(buf, sizeof(buf), "%08d%06d", time(NULL), rand()%1000000);
	*(p++) = rand()%26+'a';
	*(p++) = rand()%26+'A';
	*(p++) = rand()%10+'0';
	*(p++) = rand()%10+'0';
	*p = 0;

	obj->boundary = navi_pool_strdup(obj->pool, buf);
	return obj;
}

const char* navi_formdata_boundary(navi_formdata_t* form)
{
	return form->boundary;
}

void navi_formdata_push_plain(navi_formdata_t* form,
	const char* field_name, const unsigned char* value, size_t sz, const char* content_type,
	const char* filename)
{
	if (!form || !field_name || !strlen(field_name)) return;
	navi_formfield_t* field = (navi_formfield_t*)navi_pool_calloc(form->pool,
			1, sizeof(navi_formfield_t));

	field->field_type = FORMFIELD_PLAIN;
	field->name = navi_pool_strdup(form->pool, field_name);
	if (content_type)
		field->content_type = navi_pool_strdup(form->pool, content_type);

	if (filename)
		field->file_name = navi_pool_strdup(form->pool, filename);

	if ( sz > 0) {
		field->content.size = sz;
		field->content.mem = navi_pool_alloc(form->pool, sz);
		memcpy(field->content.mem, value, sz);
	}

	if ( form->fields == NULL)
		form->fields = navi_hash_init(form->pool);

	navi_hash_set_gr(form->fields, field_name, field);
	return;
}

void navi_formdata_push_file(navi_formdata_t* form, const char* field_name,
	int fd, off_t off, size_t sz, const char* content_type,
	const char* file_name)
{
	if (!form || !field_name || !strlen(field_name)) return;
	navi_formfield_t* field = (navi_formfield_t*)navi_pool_calloc(form->pool,
			1, sizeof(navi_formfield_t));

	field->field_type = FORMFIELD_FILE_CONTENT;
	field->name = navi_pool_strdup(form->pool, field_name);
	if (content_type)
		field->content_type = navi_pool_strdup(form->pool, content_type);
	if (file_name)
		field->file_name = navi_pool_strdup(form->pool, file_name);

	if ( sz > 0) {
		field->content.size = sz;
		field->content.fd = fd;
		field->content.fd_off = off;
	}

	if ( form->fields == NULL)
		form->fields = navi_hash_init(form->pool);

	navi_hash_set_gr(form->fields, field_name, field);
	return;
}

void navi_formdata_push_mixed_file_attach(navi_formdata_t* form, const char* mix_field,
	const char* filename, int fd, off_t off, size_t sz, const char* content_type)
{
	if (!form || !mix_field || !strlen(mix_field)) return;

	navi_formfield_t* mix = NULL;
	if ( form->fields ) {
		mix = (navi_formfield_t*)navi_hash_get_gr(form->fields, mix_field);
	}
	if (mix == NULL) {
		mix = (navi_formfield_t*)navi_pool_calloc(form->pool, 1, sizeof(navi_formfield_t));
		mix->name = navi_pool_strdup(form->pool, mix_field);
		mix->content_type = "multipart/mixed";
		char buf[40];
		char* p = buf;
		p += snprintf(buf, sizeof(buf), "06d", rand()%1000000);
		*(p++) = rand()%26+'a';
		*(p++) = rand()%26+'A';
		*(p++) = rand()%10+'0';
		*(p++) = rand()%10+'0';
		*p = 0;
		mix->mixed_attaches.mix_boundary = navi_pool_strdup(form->pool, buf);
		mix->mixed_attaches.subs_capacity = 4;
		mix->mixed_attaches.subs = (navi_formfield_t**)navi_pool_calloc(form->pool,
			4, sizeof(void*));
		navi_hash_set_gr(form->fields, mix_field, mix);

	}
	else if (mix->field_type != FORMFIELD_MIX_ATTACHMENTS) {
		return;
	}

	if (mix->mixed_attaches.subs_count == mix->mixed_attaches.subs_capacity) {
		mix->mixed_attaches.subs_capacity *= 2;
		navi_formfield_t** na = (navi_formfield_t**)navi_pool_calloc(form->pool,
			mix->mixed_attaches.subs_capacity, sizeof(void*));
		memcpy(na, mix->mixed_attaches.subs, sizeof(void*)*mix->mixed_attaches.subs_count);
	}

	navi_formfield_t* sub_field = (navi_formfield_t*)navi_pool_calloc(form->pool,
		1, sizeof(navi_formfield_t));

	sub_field->field_type = FORMFIELD_FILE_CONTENT;
	if (content_type)
		sub_field->content_type = navi_pool_strdup(form->pool, content_type);

	if (filename)
		sub_field->file_name = navi_pool_strdup(form->pool, filename);
	sub_field->content.fd = fd;
	sub_field->content.fd_off = off;
	sub_field->content.size = sz;

	mix->mixed_attaches.subs[mix->mixed_attaches.subs_count++] = sub_field;
	return;
}

void navi_formdata_push_mixed_mem_attach(navi_formdata_t* form, const char* mix_field,
	const char* filename, const unsigned char* content, size_t sz, const char* content_type)
{
	if (!form || !mix_field || !strlen(mix_field)) return;

	navi_formfield_t* mix = NULL;
	if ( form->fields ) {
		mix = (navi_formfield_t*)navi_hash_get_gr(form->fields, mix_field);
	}
	if (mix == NULL) {
		mix = (navi_formfield_t*)navi_pool_calloc(form->pool, 1, sizeof(navi_formfield_t));
		mix->name = navi_pool_strdup(form->pool, mix_field);
		mix->content_type = "multipart/mixed";
		char buf[40];
		char* p = buf;
		p += snprintf(buf, sizeof(buf), "06d", rand()%1000000);
		*(p++) = rand()%26+'a';
		*(p++) = rand()%26+'A';
		*(p++) = rand()%10+'0';
		*(p++) = rand()%10+'0';
		*p = 0;
		mix->mixed_attaches.mix_boundary = navi_pool_strdup(form->pool, buf);
		mix->mixed_attaches.subs_capacity = 4;
		mix->mixed_attaches.subs = (navi_formfield_t**)navi_pool_calloc(form->pool,
			4, sizeof(void*));
		navi_hash_set_gr(form->fields, mix_field, mix);
	}
	else if (mix->field_type != FORMFIELD_MIX_ATTACHMENTS) {
		return;
	}

	if (mix->mixed_attaches.subs_count == mix->mixed_attaches.subs_capacity) {
		mix->mixed_attaches.subs_capacity *= 2;
		navi_formfield_t** na = (navi_formfield_t**)navi_pool_calloc(form->pool,
			mix->mixed_attaches.subs_capacity, sizeof(void*));
		memcpy(na, mix->mixed_attaches.subs, sizeof(void*)*mix->mixed_attaches.subs_count);
	}

	navi_formfield_t* sub_field = (navi_formfield_t*)navi_pool_calloc(form->pool,
		1, sizeof(navi_formfield_t));

	sub_field->field_type = FORMFIELD_PLAIN;
	if (content_type)
		sub_field->content_type = navi_pool_strdup(form->pool, content_type);
	if (filename)
		sub_field->file_name = navi_pool_strdup(form->pool, filename);
	sub_field->content.mem = (unsigned char*)navi_pool_alloc(form->pool, sz);
	memcpy(sub_field->content.mem, content, sz);
	sub_field->content.size = sz;

	mix->mixed_attaches.subs[mix->mixed_attaches.subs_count++] = sub_field;
	return;
}

void navi_formdata_push_mixed_mem_attach_nocopy(navi_formdata_t* form, const char* mix_field,
	const char* filename, unsigned char* content, size_t sz, const char* content_type)
{
	if (!form || !mix_field || !strlen(mix_field)) return;

	navi_formfield_t* mix = NULL;
	if ( form->fields ) {
		mix = (navi_formfield_t*)navi_hash_get_gr(form->fields, mix_field);
	}
	if (mix == NULL) {
		mix = (navi_formfield_t*)navi_pool_calloc(form->pool, 1, sizeof(navi_formfield_t));
		mix->name = navi_pool_strdup(form->pool, mix_field);
		mix->content_type = "multipart/mixed";
		char buf[40];
		char* p = buf;
		p += snprintf(buf, sizeof(buf), "06d", rand()%1000000);
		*(p++) = rand()%26+'a';
		*(p++) = rand()%26+'A';
		*(p++) = rand()%10+'0';
		*(p++) = rand()%10+'0';
		*p = 0;
		mix->mixed_attaches.mix_boundary = navi_pool_strdup(form->pool, buf);
		mix->mixed_attaches.subs_capacity = 4;
		mix->mixed_attaches.subs = (navi_formfield_t**)navi_pool_calloc(form->pool,
			4, sizeof(void*));
		navi_hash_set_gr(form->fields, mix_field, mix);
	}
	else if (mix->field_type != FORMFIELD_MIX_ATTACHMENTS) {
		return;
	}

	if (mix->mixed_attaches.subs_count == mix->mixed_attaches.subs_capacity) {
		mix->mixed_attaches.subs_capacity *= 2;
		navi_formfield_t** na = (navi_formfield_t**)navi_pool_calloc(form->pool,
			mix->mixed_attaches.subs_capacity, sizeof(void*));
		memcpy(na, mix->mixed_attaches.subs, sizeof(void*)*mix->mixed_attaches.subs_count);
	}

	navi_formfield_t* sub_field = (navi_formfield_t*)navi_pool_calloc(form->pool,
		1, sizeof(navi_formfield_t));

	sub_field->field_type = FORMFIELD_PLAIN;
	if (content_type)
		sub_field->content_type = navi_pool_strdup(form->pool, content_type);
	if (filename)
		sub_field->file_name = navi_pool_strdup(form->pool, filename);
	sub_field->content.mem = content;
	sub_field->content.size = sz;

	mix->mixed_attaches.subs[mix->mixed_attaches.subs_count++] = sub_field;
	return;
}

#define FIELD_CONTTYPE_FORMAT "--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\nContent-Type: %s\r\n\r\n"
#define FIELD_FORMAT "--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n"
#define FIELD_MIX_FORMAT "--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\nContent-Type: multipart/mixed, boundary=%s\r\n\r\n"
#define FIELD_CONTTYPE_FILENAME_FORMAT "--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\nContent-Type: %s\r\n\r\n"
#define FIELD_FILENAME_FORMAT "--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n\r\n"

#define FIELD_CONTTYPE_FORMAT2 "\r\n--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\nContent-Type: %s\r\n\r\n"
#define FIELD_FORMAT2 "\r\n--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n"
#define FIELD_MIX_FORMAT2 "\r\n--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\nContent-Type: multipart/mixed, boundary=%s\r\n\r\n"
#define FIELD_CONTTYPE_FILENAME_FORMAT2 "\r\n--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\nContent-Type: %s\r\n\r\n"
#define FIELD_FILENAME_FORMAT2 "\r\n--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n\r\n"

#define FIELD_SUBATTACH_FORMAT "--%s\r\nContent-disposition: attachment; filename=\"%s\"\r\n\r\n"
#define FIELD_SUBATTACH_CONTTYPE_FORMAT "--%s\r\nContent-disposition: attachment; filename=\"%s\"\r\nContent-Type: \"%s\"\r\n\r\n"

#define FIELD_SUBATTACH_FORMAT2 "\r\n--%s\r\nContent-disposition: attachment; filename=\"%s\"\r\n\r\n"
#define FIELD_SUBATTACH_CONTTYPE_FORMAT2 "\r\n--%s\r\nContent-disposition: attachment; filename=\"%s\"\r\nContent-Type: \"%s\"\r\n\r\n"

const navi_buf_chain_t* navi_formdata_get_body(navi_formdata_t* form)
{
	if (!form || !form->fields || !form->fields->used) return NULL;
	if (form->out_chain == NULL) form->out_chain = navi_buf_chain_init(form->pool);

	void* it = navi_hash_iter(form->fields);
	navi_hent_t* he = NULL;
	navi_formfield_t* field;
	char tmp_buf[1024];
	off_t tmp_sz = 0;
	int cnt = 0, sub_cnt =0;
	while ( (he = navi_hash_iter_next(it)) ) {
		field = (navi_formfield_t*)he->v;
		tmp_sz = 0;
		sub_cnt = 0;
		if (field->field_type == FORMFIELD_PLAIN || field->field_type == FORMFIELD_FILE_CONTENT) {
			char* field_header = tmp_buf;
			const char* pformat = NULL;
			if (field->file_name && field->content_type) {
				pformat = cnt?FIELD_CONTTYPE_FILENAME_FORMAT2:FIELD_CONTTYPE_FILENAME_FORMAT;
				tmp_sz = snprintf(tmp_buf,sizeof(tmp_buf),pformat, form->boundary, field->name,
					field->file_name, field->content_type );
				if (tmp_sz >= sizeof(tmp_buf) ) {
					field_header = (char*)malloc(tmp_sz+1);
					sprintf(field_header, pformat, form->boundary, field->name,field->file_name, field->content_type );
				}
			}
			else if (field->file_name) {
				pformat = cnt?FIELD_FILENAME_FORMAT2:FIELD_FILENAME_FORMAT;
				tmp_sz = snprintf(tmp_buf,sizeof(tmp_buf),pformat, form->boundary,  field->name,
					field->file_name);
				if (tmp_sz >= sizeof(tmp_buf) ) {
					field_header = (char*)malloc(tmp_sz+1);
					sprintf(field_header, pformat,form->boundary,  field->name,field->file_name );
				}
			}
			else if (field->content_type) {
				pformat = cnt?FIELD_CONTTYPE_FORMAT2:FIELD_CONTTYPE_FORMAT;
				tmp_sz = snprintf(tmp_buf,sizeof(tmp_buf),pformat, form->boundary, field->name,
					field->content_type);
				if (tmp_sz >= sizeof(tmp_buf) ) {
					field_header = (char*)malloc(tmp_sz+1);
					sprintf(field_header, pformat, form->boundary, field->name,field->content_type );
				}
			}
			else {
				pformat = cnt?FIELD_FORMAT2:FIELD_FORMAT;
				tmp_sz = snprintf(tmp_buf,sizeof(tmp_buf),pformat,form->boundary,  field->name);
				if (tmp_sz >= sizeof(tmp_buf) ) {
					field_header = (char*)malloc(tmp_sz+1);
					sprintf(field_header, pformat, form->boundary, field->name);
				}
			}

			navi_buf_chain_append(form->out_chain, field_header, tmp_sz);
			if (field_header != tmp_buf)free(field_header);
			if (field->field_type == FORMFIELD_PLAIN) {
				navi_buf_chain_append(form->out_chain, field->content.mem, field->content.size);
			}
			else {
				navi_buf_chain_append_part_file(form->out_chain, field->content.fd, field->content.fd_off,
					field->content.size);
			}
		}
		else  if (field->field_type == FORMFIELD_MIX_ATTACHMENTS) {
			char* field_header = tmp_buf;
			const char* pformat = NULL;
			pformat = cnt?FIELD_MIX_FORMAT2:FIELD_MIX_FORMAT;
			tmp_sz = snprintf(tmp_buf,sizeof(tmp_buf), pformat, form->boundary, field->name,
					field->mixed_attaches.mix_boundary);
			if (tmp_sz >= sizeof(tmp_buf)) {
				field_header = (char*)malloc(tmp_sz+1);
				sprintf(field_header, pformat,form->boundary, field->name, field->mixed_attaches.mix_boundary);
			}
			navi_buf_chain_append(form->out_chain, field_header, tmp_sz);
			if (field_header != tmp_buf)free(field_header);
			int i = 0;
			navi_formfield_t* sub_field;
			for ( ; i <field->mixed_attaches.subs_count; i++) {
				sub_field = field->mixed_attaches.subs[i];

				char* field_header = tmp_buf;
				const char* pformat = NULL;
				if ( sub_field->content_type) {
					pformat = i?FIELD_SUBATTACH_CONTTYPE_FORMAT2:FIELD_SUBATTACH_CONTTYPE_FORMAT;
					tmp_sz = snprintf(tmp_buf,sizeof(tmp_buf),pformat,field->mixed_attaches.mix_boundary,
							sub_field->file_name?sub_field->file_name:"", sub_field->content_type );
					if (tmp_sz >= sizeof(tmp_buf) ) {
						field_header = (char*)malloc(tmp_sz+1);
						sprintf(field_header, pformat, field->mixed_attaches.mix_boundary,
							sub_field->file_name?sub_field->file_name:"", sub_field->content_type );
					}
				}
				else {
					pformat = i?FIELD_SUBATTACH_FORMAT2:FIELD_SUBATTACH_FORMAT;
					tmp_sz = snprintf(tmp_buf,sizeof(tmp_buf),pformat, field->mixed_attaches.mix_boundary,
							sub_field->file_name?sub_field->file_name:"");
					if (tmp_sz >= sizeof(tmp_buf) ) {
						field_header = (char*)malloc(tmp_sz+1);
						sprintf(field_header, pformat, field->mixed_attaches.mix_boundary,
							sub_field->file_name?sub_field->file_name:"" );
					}
				}


				navi_buf_chain_append(form->out_chain, field_header, tmp_sz);
				if (field_header != tmp_buf)free(field_header);
				if (sub_field->field_type == FORMFIELD_PLAIN) {
					navi_buf_chain_append(form->out_chain, sub_field->content.mem, sub_field->content.size);
				}
				else {
					navi_buf_chain_append_part_file(form->out_chain, sub_field->content.fd, sub_field->content.fd_off,
						sub_field->content.size);
				}
			}
			sprintf(tmp_buf, "\r\n--%s--\r\n", field->mixed_attaches.mix_boundary);
			navi_buf_chain_append(form->out_chain, tmp_buf, strlen(tmp_buf));
		}

		cnt++;
	}
	sprintf(tmp_buf, "\r\n--%s--\r\n", form->boundary);
	navi_buf_chain_append(form->out_chain, tmp_buf, strlen(tmp_buf));
	navi_hash_iter_destroy(it);

	return form->out_chain;
}

void navi_formdata_destroy(navi_formdata_t* form)
{
	navi_pool_destroy(form->pool);
}
