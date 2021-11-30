#ifndef __NGX_HTTP_HERCULES
#define __NGX_HTTP_HERCULES
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event_openssl.h>
#include <endian.h>
#include <libhercules.h>

#include "ngx_http_hercules_log_struct.h"
#include "ngx_http_hercules_log_network.h"

#define HERCULES_LOG_BUFFER_SIZE 1024 * 1024 * 32
#define HERCULES_LOG_BUFFER_FLUSH_TIME 10 * 1000
#define HERCULES_LOG_MAX_SOCKET_SIZE 1
/* #define USE_RDSEED */

#ifdef USE_RDSEED
#include <immintrin.h>
#endif


#define STR_FROM_NGX_STR(variable, pool, value) \
  char* variable = ngx_palloc(pool, sizeof(char) * (value.len + 1)); \
  variable[value.len] = '\0'; \
  ngx_memcpy(variable, value.data, value.len);
#endif