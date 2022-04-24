#ifndef __NGX_HTTP_HERCULES_STRUCT
#define __NGX_HTTP_HERCULES_STRUCT
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_thread_pool.h>

#define NGX_HERCULES_CHUNK_NULL 0
#define NGX_HERCULES_CHUNK_ON_WRITE 1
#define NGX_HERCULES_CHUNK_ON_READ 2

typedef struct {
    ngx_buf_t*         buffer;
    uint8_t            retries_counter;
} ngx_http_hercules_chunk_t;

typedef struct {
    ngx_http_hercules_chunk_t*     chunk;
    ngx_queue_t                    queue;
} ngx_http_hercules_queue_task_t;

typedef struct ngx_http_hercules_ctx_s {
    ngx_pool_t*                    pool;
    ngx_log_t*                     log;
    ngx_queue_t*                   task_queue;
    ngx_http_hercules_chunk_t*     active_chunk;
    ngx_addr_t*                    addr;
    ngx_buf_t*                     response;
    ngx_connection_t*              peer;
    ngx_int_t                      active_chunk_status;
    ngx_msec_t                     read_timeout;
    ngx_msec_t                     write_timeout;
} ngx_http_hercules_ctx_t;

typedef struct {
    ngx_log_t*               log;
    ngx_buf_t*               buffer;
    ngx_event_t*             event;
    ngx_pool_t*              pool;
    ngx_connection_t*        connection;
    ngx_queue_t*             sockets;
    ngx_thread_pool_t*       thread_pool;
    ngx_http_hercules_ctx_t* ctx;
    ngx_msec_t               flush;
    ngx_int_t                node_var_inx;
} ngx_http_hercules_main_conf_t;
#endif