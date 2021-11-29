#ifndef __NGX_HTTP_HERCULES_NETWORK
#define __NGX_HTTP_HERCULES_NETWORK
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_thread_pool.h>
#include <pthread.h>
#include "ngx_http_hercules_log_struct.h"

#define THREAD_SENDER
/* #define EVENT_LOOP_SENDER */

#define HERCULES_SENDER_HOST "127.0.0.1"
#define HERCULES_SENDER_POST 2480
#define HERCULES_THREAD_POOL_NAME "hercules"
#define HERCULES_THREAD_RESEND_COUNTER 3
#define HERCULES_THREAD_RESEND_BUCKETS_SIZE 8
#define HERCULES_THREAD_SEND_TIMEOUT 5

#include "ngx_http_hercules_log_module.h"

#ifdef THREAD_SENDER
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static void ngx_http_hercules_thread_sender(void* data, ngx_log_t* log);
static void ngx_http_hercules_thread_sender_completion(ngx_event_t* ev);
void ngx_http_hercules_send_metrics(ngx_http_hercules_main_conf_t* conf, u_int8_t direct);
#endif

#ifdef EVENT_LOOP_SENDER
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
static inline void ngx_http_hercules_destroy_connection(ngx_http_hercules_main_conf_t* conf, ngx_connection_t* connection);
void ngx_http_hercules_send_metrics(ngx_http_hercules_main_conf_t* conf);
#endif

#endif