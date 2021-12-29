#ifndef __NGX_HTTP_HERCULES_NETWORK
#define __NGX_HTTP_HERCULES_NETWORK
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_thread_pool.h>
#include <pthread.h>
#include "ngx_http_hercules_log_struct.h"

/* #define THREAD_SENDER */
#define EVENT_LOOP_SENDER

#define HERCULES_SENDER_HOST "127.0.0.1"
#define HERCULES_SENDER_PORT 2480
#define HERCULES_SENDER_HOST_PORT "127.0.0.1:2480"
#define HERCULES_THREAD_POOL_NAME "hercules"
#define HERCULES_THREAD_RESEND_COUNTER 3
#define HERCULES_THREAD_RESEND_BUCKETS_SIZE 8
#define HERCULES_THREAD_SEND_TIMEOUT 5

#define HERCULES_RESEND_COUNTER 3
#define HERCULES_SENDER_RESPONSE_SIZE 8
#define HERCULES_SEND_TIMEOUT_IN_SECONDS 5
#define HERCULES_SEND_TIMEOUT HERCULES_SEND_TIMEOUT_IN_SECONDS * 1000

#include "ngx_http_hercules_log_module.h"

#ifdef THREAD_SENDER
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void ngx_http_hercules_thread_sender(void* data, ngx_log_t* log);
void ngx_http_hercules_thread_sender_completion(ngx_event_t* ev);
void ngx_http_hercules_send_metrics(ngx_http_hercules_main_conf_t* conf, u_int8_t direct);
#endif

#ifdef EVENT_LOOP_SENDER
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static inline ngx_int_t ngx_http_hercules_initialize_ctx(ngx_http_hercules_main_conf_t* conf){
    ngx_http_hercules_ctx_t* ctx = ngx_palloc(conf->pool, sizeof(ngx_http_hercules_ctx_t));
    ngx_memzero(ctx, sizeof(ngx_http_hercules_ctx_t));
    conf->ctx = ctx;
    ctx->pool = conf->pool;
    ctx->log = conf->pool->log;

    ctx->task_queue = ngx_palloc(ctx->pool, sizeof(ngx_queue_t));
    if (ctx->task_queue == NULL){
        return NGX_ERROR;
    }
    ngx_queue_init(ctx->task_queue);

    ctx->timeout = HERCULES_SEND_TIMEOUT;

    ctx->response = ngx_create_temp_buf(ctx->pool, HERCULES_SENDER_RESPONSE_SIZE);
    if (ctx->response == NULL){
        return NGX_ERROR;
    }

    ctx->addr = ngx_pcalloc(ctx->pool, sizeof(ngx_addr_t));
    if (ctx->addr == NULL){
        return NGX_ERROR;
    }
    ngx_str_t host = ngx_string(HERCULES_SENDER_HOST);
    if (ngx_parse_addr(ctx->pool, ctx->addr, host.data, host.len) != NGX_OK){
        return NGX_ERROR;
    }
    ngx_inet_set_port(ctx->addr->sockaddr, (in_port_t) HERCULES_SENDER_PORT);
    ngx_str_t host_port = ngx_string(HERCULES_SENDER_HOST_PORT);
    ctx->addr->name = host_port;
    return NGX_OK;
}

void ngx_http_hercules_send_metrics(ngx_http_hercules_main_conf_t* conf);
void ngx_http_hercules_send_on_exit(ngx_http_hercules_main_conf_t* conf);
#endif

#endif