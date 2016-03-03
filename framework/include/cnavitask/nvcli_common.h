/** \brief 
 * nvcli_common.h
 *  Created on: 2015-1-19
 *      Author: li.lei
 *  brief: 
 */

#ifndef NVCLI_COMMON_H_
#define NVCLI_COMMON_H_

#include "navi_common_define.h"
#include <jansson.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum _vncli_error_e
{
	NVCLI_CONNECTING_TIMEDOUT,
	NVCLI_CONNECTING_FAILED,
	NVCLI_OUTPUT_INCOMPLETE,
	NVCLI_UNEXPECTED_INPUT,
	NVCLI_SEND_TIMEDOUT,
	NVCLI_RESP_TIMEDOUT,
	NVCLI_PEER_CLOSE,
	NVCLI_BROKEN,
	NVCLI_PROTO_ERROR
} nvcli_error_e;

#ifdef __cplusplus
}
#endif

#endif /* NVCLI_COMMON_H_ */
