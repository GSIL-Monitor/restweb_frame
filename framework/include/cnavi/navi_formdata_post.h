/*
 * navi_formdata_post.h
 *
 *  Created on: 2015Äê6ÔÂ28ÈÕ
 *      Author: L-F000000-PC
 */

#ifndef NAVI_FORMDATA_POST_H_
#define NAVI_FORMDATA_POST_H_

#include "navi_buf_chain.h"
#include "navi_simple_hash.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum navi_formfiled_type_s
{
	FORMFIELD_PLAIN,
	FORMFIELD_FILE_CONTENT,
	FORMFIELD_MIX_ATTACHMENTS
} navi_formfield_type_e;

typedef struct navi_formfield_s
{
	char* name;
	char* content_type;
	char* file_name;
	navi_formfield_type_e field_type;
	union {
		struct {
			size_t size;
			union {
				struct {
					int fd;
					off_t fd_off;
				};
				unsigned char* mem;
			};
		} content;

		struct {
			struct navi_formfield_s** subs;
			int subs_count;
			int subs_capacity;
			char* mix_boundary;
		} mixed_attaches;
	};
} navi_formfield_t;

typedef struct navi_formdata_s
{
	char* boundary;
	navi_hash_t* fields;
	navi_buf_chain_t* out_chain;
	navi_pool_t pool[0];
} navi_formdata_t;

navi_formdata_t* navi_formdata_create();

const char* navi_formdata_boundary(navi_formdata_t* form);

void navi_formdata_push_plain(navi_formdata_t* form,
	const char* field_name, const unsigned char* value, size_t sz, const char* content_type,
	const char* filename_attr);

void navi_formdata_push_file(navi_formdata_t* form, const char* field_name,
	int fd, off_t off, size_t sz, const char* content_type,
	const char* filename_attr);

void navi_formdata_push_mixed_file_attach(navi_formdata_t* form, const char* mix_field,
	const char* filename, int fd, off_t off, size_t sz, const char* content_type);

void navi_formdata_push_mixed_mem_attach(navi_formdata_t* form, const char* mix_field,
	const char* filename, const unsigned char* content, size_t sz, const char* content_type);

void navi_formdata_push_mixed_mem_attach_nocopy(navi_formdata_t* form, const char* mix_field,
	const char* filename, unsigned char* content, size_t sz, const char* content_type);

const navi_buf_chain_t* navi_formdata_get_body(navi_formdata_t* form);

void navi_formdata_destroy(navi_formdata_t* form);

#ifdef __cplusplus
}
#endif

#endif /* INCLUDE_CNAVI_NAVI_FORMDATA_POST_H_ */
