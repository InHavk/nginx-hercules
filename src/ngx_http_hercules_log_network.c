#include "ngx_http_hercules_log_network.h"

static void ngx_http_hercules_send_chunk(ngx_http_hercules_ctx_t* ctx);
static inline ngx_int_t ngx_http_hercules_connect(ngx_http_hercules_ctx_t* ctx);
static void ngx_http_hercules_read_handler(ngx_event_t *rev);
static void ngx_http_hercules_write_handler(ngx_event_t *wev);
static inline void ngx_http_hercules_error(ngx_http_hercules_ctx_t* ctx);


void ngx_http_hercules_send_metrics(ngx_http_hercules_main_conf_t* conf){
    ngx_http_hercules_ctx_t* ctx = conf->ctx;
    ngx_pool_t* pool = ctx->pool;
    ngx_queue_t* task_queue = ctx->task_queue;
    

    size_t buffer_size = conf->buffer->pos - conf->buffer->start;
    uint64_t be_buffer_size = htobe64(buffer_size);
    const size_t size_of_buffer_size = sizeof(uint64_t);
    if(buffer_size > 0){
        /* buffer */
        ngx_buf_t* buffer = ngx_create_temp_buf(pool, buffer_size + size_of_buffer_size);
        if(buffer == NULL){
            return;
        }
        ngx_memcpy(buffer->start, &be_buffer_size, size_of_buffer_size);
        ngx_memcpy(buffer->start + size_of_buffer_size, conf->buffer->start, buffer_size);

        /* reset buffer */
        conf->buffer->pos = conf->buffer->start;

        /* chunk */
        ngx_http_hercules_chunk_t* chunk = ngx_palloc(pool, sizeof(ngx_http_hercules_chunk_t));
        if(chunk == NULL){
            ngx_pfree(pool, buffer->start);
            ngx_pfree(pool, buffer);
            return;
        }
        chunk->buffer = buffer;
        chunk->retries_counter = 0;

        /* queue */
        ngx_http_hercules_queue_task_t* last_task = ngx_palloc(pool, sizeof(ngx_http_hercules_queue_task_t));
        if(last_task == NULL){
            ngx_pfree(pool, buffer->start);
            ngx_pfree(pool, buffer);
            ngx_pfree(pool, chunk);
            return;
        }
        last_task->chunk = chunk;
        ngx_queue_insert_head(task_queue, &last_task->queue);
    }

    ngx_http_hercules_send_chunk(ctx);
}

static void ngx_http_hercules_send_chunk(ngx_http_hercules_ctx_t* ctx){
    ngx_int_t rc;
    ngx_pool_t* pool = ctx->pool;
    ngx_queue_t* task_queue = ctx->task_queue;
    ngx_queue_t* q = ngx_queue_head(task_queue);

    if(ctx->active_chunk != NULL){
        return;
    }
    if (q == ngx_queue_sentinel(task_queue)){
        return;
    }
    
    ngx_http_hercules_queue_task_t* q_task = ngx_queue_data(q, ngx_http_hercules_queue_task_t, queue);
    ctx->active_chunk = q_task->chunk;
    ctx->active_chunk_status = NGX_HERCULES_CHUNK_ON_WRITE;
    ngx_queue_remove(q);
    ngx_pfree(pool, q_task);

    rc = NGX_OK;

    if (ctx->peer == NULL){
        rc = ngx_http_hercules_connect(ctx);
        if(rc == NGX_ERROR){
            goto error;
        }
        ctx->peer->data = ctx;
        ctx->peer->read->handler = ngx_http_hercules_read_handler;
        ctx->peer->write->handler = ngx_http_hercules_write_handler;
    
        ngx_add_timer(ctx->peer->write, ctx->timeout);
    }

    if(rc == NGX_OK){
        ngx_http_hercules_write_handler(ctx->peer->write);
    }

    return;
error:
    if (ctx->peer != NULL){
        ngx_close_connection(ctx->peer);
        ctx->peer = NULL;
    }
    ngx_http_hercules_error(ctx);
}

static inline ngx_int_t ngx_http_hercules_connect(ngx_http_hercules_ctx_t* ctx){
    ngx_socket_t      s;
    ngx_connection_t  *c;
    ngx_event_t       *rev, *wev;
    ngx_int_t         rc;
    ngx_err_t         err;
    ngx_int_t         event;
    ngx_addr_t* addr = ctx->addr;

    s = ngx_socket(addr->sockaddr->sa_family, SOCK_STREAM, 0);

    if (s == (ngx_socket_t) NGX_ERROR) {
        return (ngx_int_t) s;
    }

    c = ngx_get_connection(s, ctx->log);

    if (c == NULL){
        if (ngx_close_socket(s) == NGX_ERROR){
            //err
        }
        return NGX_ERROR;
    }

    if (ngx_nonblocking(s) == NGX_ERROR){
        ngx_close_connection(c);
        return NGX_ERROR;
    }

    rev = c->read;
    wev = c->write;

    rev->log = ctx->log;
    wev->log = ctx->log;

    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    c->start_time = ngx_current_msec;

    if (ngx_add_conn) {
        if (ngx_add_conn(c) == NGX_ERROR){
            ngx_close_connection(c);
            return NGX_ERROR;
        }
    }

    rc = connect(s, addr->sockaddr, addr->socklen);
    if(rc == NGX_ERROR){
        err = ngx_socket_errno;
        if (err != NGX_EINPROGRESS){
            ngx_close_connection(c);
            return NGX_ERROR;
        }
    }

    ctx->peer = c;

    if (ngx_add_conn){
        if (rc == NGX_ERROR){
            return NGX_AGAIN;
        }
        wev->ready = 1;
        return NGX_OK;
    }

    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {
        event = NGX_CLEAR_EVENT;
    } else {
        event = NGX_LEVEL_EVENT;
    }

    if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK){
        ngx_close_connection(c);
        ctx->peer = NULL;
        return NGX_ERROR;
    }

    if (rc == NGX_ERROR) {
        if (ngx_add_event(wev, NGX_WRITE_EVENT, event) != NGX_OK){
            ngx_close_connection(c);
            ctx->peer = NULL;
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    wev->ready = 1;

    return NGX_OK;
}

/*static void ngx_http_hercules_dumb_handler(ngx_event_t *ev){
    return;
}*/

static void ngx_http_hercules_read_handler(ngx_event_t *rev){
    ngx_connection_t *c = rev->data;
    ngx_http_hercules_ctx_t* ctx = c->data;

    if (ctx->active_chunk_status == NGX_HERCULES_CHUNK_NULL){
        if (rev->timer_set) {
            ngx_del_timer(rev);
        }
        return;
    }

    if (ctx->active_chunk_status == NGX_HERCULES_CHUNK_ON_WRITE){
        if (rev->timer_set) {
            ngx_del_timer(rev);
        }
        goto error;
    }

    if (rev->timedout){
        ngx_log_error(NGX_LOG_ERR, ctx->log, NGX_ETIMEDOUT, "hercules sender timed out");
        goto error;
    }

    ssize_t recv_size = ngx_recv(c, ctx->response->start, HERCULES_SENDER_RESPONSE_SIZE);

    if (recv_size != HERCULES_SENDER_RESPONSE_SIZE){
        goto error;
    }

    if (ngx_memcmp(ctx->active_chunk->buffer->start, ctx->response->start, HERCULES_SENDER_RESPONSE_SIZE) != 0){
        goto error;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    ngx_pfree(ctx->pool, ctx->active_chunk->buffer->start);
    ngx_pfree(ctx->pool, ctx->active_chunk->buffer);
    ngx_pfree(ctx->pool, ctx->active_chunk);
    ctx->active_chunk = NULL;
    ctx->active_chunk_status = NGX_HERCULES_CHUNK_NULL;

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        goto error;
    }

    ngx_http_hercules_send_chunk(ctx);
    return;

error:
    ngx_close_connection(c);
    ctx->peer = NULL;
    ngx_http_hercules_error(ctx);
}

static void ngx_http_hercules_write_handler(ngx_event_t *wev){
    ngx_connection_t *c = wev->data;
    ngx_http_hercules_ctx_t* ctx = c->data;

    if (ctx->active_chunk_status == NGX_HERCULES_CHUNK_NULL){
        if (wev->timer_set) {
            ngx_del_timer(wev);
        }
        return;
    }
    if (wev->timedout){
        ngx_log_error(NGX_LOG_ERR, ctx->log, NGX_ETIMEDOUT, "hercules sender timed out");
        goto error;
    }

    ngx_buf_t* buffer = ctx->active_chunk->buffer;
    size_t buffer_size = buffer->end - buffer->pos;

    ssize_t sended_size = ngx_send(c, buffer->pos, buffer_size);
    if (sended_size == NGX_ERROR){
        goto error;
    }

    if (sended_size > 0){
        buffer->pos += sended_size;

        if ((size_t) sended_size == buffer_size){
            if (wev->timer_set) {
                ngx_del_timer(wev);
            }
            ctx->active_chunk_status = NGX_HERCULES_CHUNK_ON_READ;
            ngx_add_timer(ctx->peer->read, ctx->timeout);
            return;
        }

        ngx_int_t hwe = ngx_handle_write_event(wev, 0);
        if (hwe != NGX_OK){
            goto error;
        }
    }

    return;
error:
    ngx_close_connection(c);
    ctx->peer = NULL;
    ngx_http_hercules_error(ctx);
}

static inline void ngx_http_hercules_error(ngx_http_hercules_ctx_t* ctx){
    if (ctx->active_chunk->retries_counter >= HERCULES_RESEND_COUNTER){
        ngx_pfree(ctx->pool, ctx->active_chunk->buffer->start);
        ngx_pfree(ctx->pool, ctx->active_chunk->buffer);
        ngx_pfree(ctx->pool, ctx->active_chunk);
        ctx->active_chunk = NULL;
        ctx->active_chunk_status = NGX_HERCULES_CHUNK_NULL;
        return;
    }

    ngx_http_hercules_queue_task_t* last_task = ngx_palloc(ctx->pool, sizeof(ngx_http_hercules_queue_task_t));
    if(last_task == NULL){
        ngx_pfree(ctx->pool, ctx->active_chunk->buffer->start);
        ngx_pfree(ctx->pool, ctx->active_chunk->buffer);
        ngx_pfree(ctx->pool, ctx->active_chunk);
    } else {
        ctx->active_chunk->retries_counter += 1;
        last_task->chunk = ctx->active_chunk;
        ngx_queue_insert_tail(ctx->task_queue, &last_task->queue);
    }
    ctx->active_chunk = NULL;
    ctx->active_chunk_status = NGX_HERCULES_CHUNK_NULL;
}

void ngx_http_hercules_send_on_exit(ngx_http_hercules_main_conf_t* conf){
    ngx_http_hercules_ctx_t* ctx = conf->ctx;

    ngx_queue_t* q = ngx_queue_head(ctx->task_queue);
    if(q == ngx_queue_sentinel(ctx->task_queue)){
        return;
    }

    struct timeval send_timeout;
    send_timeout.tv_sec = HERCULES_SEND_TIMEOUT_IN_SECONDS;
    send_timeout.tv_usec = 0;

    int logic_true = 1;

    ngx_socket_t socket_fd = -1;
    socket_fd = ngx_socket(AF_INET, SOCK_STREAM, 0);
    if(socket_fd < 0){
        goto error;
    }
    if(setsockopt(socket_fd, SOL_SOCKET, SO_KEEPALIVE, &logic_true, sizeof(logic_true)) < 0){
        goto error;
    }
    if(setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout)) < 0){
        goto error;
    }
    if(setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &send_timeout, sizeof(send_timeout)) < 0){
        goto error;
    }

    if(connect(socket_fd, ctx->addr->sockaddr, ctx->addr->socklen) < 0){
            goto error;
    }

    ngx_buf_t* response = ngx_create_temp_buf(ctx->pool, HERCULES_SENDER_RESPONSE_SIZE);

    while(q != ngx_queue_sentinel(ctx->task_queue)){
        ngx_http_hercules_queue_task_t* q_task = ngx_queue_data(q, ngx_http_hercules_queue_task_t, queue);
        ssize_t buffer_size = q_task->chunk->buffer->end - q_task->chunk->buffer->start;
        ssize_t sended_bytes = send(socket_fd, q_task->chunk->buffer->start, buffer_size, 0);
        if (sended_bytes != buffer_size){
            goto error;
        }
        ssize_t received_bytes = recv(socket_fd, response->start, HERCULES_SENDER_RESPONSE_SIZE, MSG_WAITALL);
        if (received_bytes != HERCULES_SENDER_RESPONSE_SIZE){
            goto error;
        }
    }

error:
    if(socket_fd > 0){
        close(socket_fd);
    }
}