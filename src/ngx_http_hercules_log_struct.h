#ifndef __NGX_HTTP_HERCULES_STRUCT
#define __NGX_HTTP_HERCULES_STRUCT
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_thread_pool.h>

typedef struct {
    ngx_log_t*         log;
    ngx_buf_t*         buffer;
    ngx_queue_t*       task_queue;
    ngx_event_t*       event;
    ngx_pool_t*        pool;
    ngx_connection_t*  connection;
    ngx_queue_t*       sockets;
    ngx_thread_pool_t* thread_pool;
    ngx_msec_t         flush;
    ngx_int_t          node_var_inx;
} ngx_http_hercules_main_conf_t;

typedef struct {
    ngx_thread_task_t*             task;
    ngx_http_hercules_main_conf_t* conf;
    ngx_buf_t*                     buffer;
    uint8_t                        counter;
    uint8_t                        status;
    int                            socket;
} ngx_http_hercules_thread_sender_ctx_t;

typedef struct {
    ngx_buf_t*         buffer;
    uint8_t            counter;
    ngx_queue_t        queue;
} ngx_http_hercules_thread_queue_task_t;

typedef struct {
    int                socket;
    ngx_queue_t        queue;
} ngx_http_hercules_thread_queue_socket_t;

typedef struct {
    ngx_http_hercules_main_conf_t* conf;
    ngx_buf_t*                     buffer;
    ngx_connection_t*              connection;
} ngx_http_hercules_chunk_t;

#endif