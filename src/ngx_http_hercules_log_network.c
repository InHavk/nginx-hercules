#include "ngx_http_hercules_log_network.h"

#ifdef THREAD_SENDER
void ngx_http_hercules_thread_sender(void* data, ngx_log_t* log){
    /* executed in thread */
    ngx_http_hercules_thread_sender_ctx_t* ctx = data;
    ngx_buf_t* buffer = ctx->buffer;

    struct sockaddr_in server_addr;
    int logic_true = 1;
    struct timeval send_timeout;
    send_timeout.tv_sec = HERCULES_THREAD_SEND_TIMEOUT;
    send_timeout.tv_usec = 0;
    ngx_socket_t* socket_fd = &ctx->socket;

    uint8_t retries = 0;
    ctx->counter++;
reconnect:
    if(*socket_fd < 0){
        *socket_fd = ngx_socket(AF_INET, SOCK_STREAM, 0);
        if(*socket_fd < 0){
            goto error;
        }
        if(setsockopt(*socket_fd, SOL_SOCKET, SO_KEEPALIVE, &logic_true, sizeof(logic_true)) < 0){
            goto error;
        }
        if(setsockopt(*socket_fd, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout)) < 0){
            goto error;
        }
        if(setsockopt(*socket_fd, SOL_SOCKET, SO_RCVTIMEO, &send_timeout, sizeof(send_timeout)) < 0){
            goto error;
        }
        ngx_memzero(&server_addr, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(HERCULES_SENDER_POST);
        inet_pton(AF_INET, HERCULES_SENDER_HOST, &server_addr.sin_addr);
        if(connect(*socket_fd, &server_addr, sizeof(server_addr)) < 0){
            goto error;
        }
    }

    ssize_t sended_bytes = 0;
    ssize_t received_bytes = 0;
    uint64_t full_size_be = *(u_int64_t*) buffer->start;
    uint64_t return_code_be = 0;
    buffer->pos = buffer->start;
    for(size_t size_of_bucket = buffer->end - buffer->pos; size_of_bucket > 0; size_of_bucket = buffer->end - buffer->pos){
        sended_bytes = send(*socket_fd, buffer->pos, size_of_bucket, 0);
        if(sended_bytes < 0) {
            goto error;
        }
        buffer->pos += sended_bytes;
        if(buffer->pos == buffer->end){
            received_bytes = recv(*socket_fd, &return_code_be, 8, MSG_WAITALL);
            if (received_bytes < 0) {
                goto error;
            }
            if(return_code_be != full_size_be){
                goto error;
            }
        }
    }

    ctx->status = 1;
    return;
error:
    if(*socket_fd > 0){
        close(*socket_fd);
        *socket_fd = -2;
    }
    if(retries == 0){
        retries++;
        goto reconnect;
    }
    return;
}

void ngx_http_hercules_thread_sender_completion(ngx_event_t* ev){
    ngx_http_hercules_thread_sender_ctx_t* ctx = ev->data;
    ngx_http_hercules_main_conf_t* conf = ctx->conf;
    ngx_pool_t* pool = conf->pool;
    ngx_thread_task_t* task = ctx->task;
    ngx_queue_t* task_queue = conf->task_queue;
    ngx_event_t* event = conf->event;

    if(ctx->status == 0 && ctx->counter < HERCULES_THREAD_RESEND_COUNTER){
        ngx_http_hercules_thread_queue_task_t* last_task = ngx_palloc(pool, sizeof(ngx_http_hercules_thread_queue_task_t));
        if(last_task == NULL){
            return;
        }
        last_task->buffer = ctx->buffer;
        last_task->counter = ctx->counter;
        ngx_queue_insert_tail(task_queue, &last_task->queue);
    } else {
        ngx_pfree(pool, ctx->buffer->start);
        ngx_pfree(pool, ctx->buffer);
    }

    ngx_http_hercules_thread_queue_socket_t* s = ngx_palloc(conf->pool, sizeof(ngx_http_hercules_thread_queue_socket_t));
    if(s == NULL){
        return;
    }
    s->socket = ctx->socket;
    ngx_queue_insert_head(conf->sockets, &s->queue);

    ngx_pfree(pool, task);
    if(ngx_queue_head(task_queue) != ngx_queue_sentinel(task_queue) && !event->timer_set){
        ngx_event_add_timer(event, conf->flush);
    }
    
}

void ngx_http_hercules_send_metrics(ngx_http_hercules_main_conf_t* conf, u_int8_t direct){
    ngx_thread_task_t* task;
    ngx_http_hercules_thread_sender_ctx_t* ctx;
    ngx_buf_t* buffer;
    ngx_pool_t* pool = conf->pool;
    ngx_thread_pool_t* thread_pool = conf->thread_pool;
    ngx_queue_t* task_queue = conf->task_queue;

    /* copy buffer */
    size_t buffer_size = conf->buffer->pos - conf->buffer->start;
    uint64_t buffer_size_64 = htobe64(buffer_size);
    size_t size_of_buffer_size_64 = sizeof(uint64_t);
    if(buffer_size > 0){
        buffer = ngx_create_temp_buf(pool, buffer_size + size_of_buffer_size_64);
        if(buffer == NULL){
            return;
        }
        ngx_memcpy(buffer->start + size_of_buffer_size_64, conf->buffer->start, buffer_size);
        ngx_memcpy(buffer->start, &buffer_size_64, size_of_buffer_size_64);

        /* reset buffer */
        conf->buffer->pos = conf->buffer->start;

        ngx_http_hercules_thread_queue_task_t* last_task = ngx_palloc(pool, sizeof(ngx_http_hercules_thread_queue_task_t));
        if(last_task == NULL){
            return;
        }
        last_task->buffer = buffer;
        last_task->counter = 0;
        ngx_queue_insert_head(task_queue, &last_task->queue);
    }
    
    /* create thread tasks for all values in task_queue */
    ngx_queue_t* q = ngx_queue_head(task_queue);
    ngx_queue_t* current_q;
    ngx_http_hercules_thread_queue_task_t* q_task;
    ngx_http_hercules_thread_queue_socket_t* socket;
    while(q != ngx_queue_sentinel(task_queue)){
        /* get socket or break */
        ngx_queue_t* s = ngx_queue_head(conf->sockets);
        if(s == ngx_queue_sentinel(conf->sockets)){
            break;
        }

        socket = ngx_queue_data(s, ngx_http_hercules_thread_queue_socket_t, queue);

        /* create task and load task context */
        if(!direct){
            task = ngx_thread_task_alloc(pool, sizeof(ngx_http_hercules_thread_sender_ctx_t));
            if(task == NULL){
                return;
            }
            ctx = task->ctx;
        } else {
            if(conf->buffer == NULL){
                return;
            }
            task = NULL;
            ctx = ngx_palloc(pool, sizeof(ngx_http_hercules_thread_sender_ctx_t));
        }
        q_task = ngx_queue_data(q, ngx_http_hercules_thread_queue_task_t, queue);

        ctx->conf = conf;
        ctx->task = task;
        ctx->status = 0;
        ctx->buffer = q_task->buffer;
        ctx->counter = q_task->counter;
        ctx->socket = socket->socket;

        /* set task handlers and push it into thread pool */
        if(!direct){
            task->handler = ngx_http_hercules_thread_sender;
            task->event.handler = ngx_http_hercules_thread_sender_completion;
            task->event.data = ctx;
            ngx_thread_task_post(thread_pool, task);
        } else {
            ngx_http_hercules_thread_sender(ctx, NULL);
        }

        current_q = q;
        q = ngx_queue_next(current_q);
        ngx_queue_remove(current_q);
        ngx_pfree(pool, q_task);
        ngx_queue_remove(s);
        ngx_pfree(pool, socket);
    }
}

#endif

#ifdef EVENT_LOOP_SENDER
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

    if (ctx->peer.connection == NULL){
        rc = ngx_http_hercules_connect(ctx);
        if(rc == NGX_BUSY || rc == NGX_DECLINED){
            goto error;
        }
    }

    if (ctx->peer.connection->write->handler != ngx_http_hercules_write_handler){
        ctx->peer.connection->write->handler = ngx_http_hercules_write_handler;
        if (ngx_handle_read_event(ctx->peer.connection->read, 0) != NGX_OK) {
            goto error;
        }
        if (ngx_handle_write_event(ctx->peer.connection->write, 0) != NGX_OK) {
            goto error;
        }
        ngx_add_timer(ctx->peer.connection->write, ctx->timeout);
        ngx_http_hercules_write_handler(ctx->peer.connection->write);
    }
    return;
error:
    if (ctx->peer.connection != NULL){
        ngx_close_connection(ctx->peer.connection);
        ctx->peer.connection = NULL;
    }
    ngx_http_hercules_error(ctx);
}

static inline ngx_int_t ngx_http_hercules_connect(ngx_http_hercules_ctx_t* ctx){
    ngx_addr_t* addr = ctx->addr;

    ctx->peer.sockaddr = addr->sockaddr;
    ctx->peer.socklen = addr->socklen;
    ctx->peer.name = &addr->name;
    ctx->peer.get = ngx_event_get_peer;
    ctx->peer.log = ctx->log;
    ctx->peer.log_error = NGX_ERROR_ERR;

    ngx_int_t rc = ngx_event_connect_peer(&ctx->peer);

    if(rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED){
        return rc;
    }

    ctx->peer.connection->data = ctx;
    ctx->peer.connection->pool = ctx->pool;
    ctx->peer.connection->read->handler = ngx_http_hercules_read_handler;
    ctx->peer.connection->write->handler = ngx_http_hercules_write_handler;

    ngx_add_timer(ctx->peer.connection->write, ctx->timeout);

    if(rc == NGX_OK){
        ngx_http_hercules_write_handler(ctx->peer.connection->write);
    }

    return rc;
}

static void ngx_http_hercules_dumb_handler(ngx_event_t *ev){
    return;
}

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

    ngx_http_hercules_send_chunk(ctx);
    return;

error:
    ngx_close_connection(c);
    ctx->peer.connection = NULL;
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
            wev->handler = ngx_http_hercules_dumb_handler;
            ngx_add_timer(ctx->peer.connection->read, ctx->timeout);
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
    ctx->peer.connection = NULL;
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

    if(connect(socket_fd, ctx->peer.sockaddr, ctx->peer.socklen) < 0){
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
#endif