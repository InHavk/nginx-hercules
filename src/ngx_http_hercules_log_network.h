#ifndef __NGX_HTTP_HERCULES_NETWORK
#define __NGX_HTTP_HERCULES_NETWORK
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_thread_pool.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ngx_http_hercules_log_struct.h"
#include "ngx_http_hercules_log_module.h"

#define HERCULES_SENDER_HOST "127.0.0.1"
#define HERCULES_SENDER_PORT 2480
#define HERCULES_SENDER_HOST_PORT "127.0.0.1:2480"

#define HERCULES_RESEND_COUNTER 3
#define HERCULES_SENDER_RESPONSE_SIZE 8
#define HERCULES_READ_TIMEOUT 5000
#define HERCULES_WRITE_TIMEOUT 30000
#define HERCULES_TIMEOUT 60000
#define HERCULES_TIMEOUT_RETRIES 1000

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

    ctx->read_timeout = HERCULES_READ_TIMEOUT;
    ctx->write_timeout = HERCULES_WRITE_TIMEOUT;

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