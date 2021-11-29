#include "ngx_http_hercules_log_network.h"

#ifdef THREAD_SENDER
static void ngx_http_hercules_thread_sender(void* data, ngx_log_t* log){
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
    uint8_t return_code[4] = {0x00, 0x00, 0x00, 0x00};
    buffer->pos = buffer->start;
    for(size_t size_of_bucket = buffer->end - buffer->pos; size_of_bucket > 0; size_of_bucket = buffer->end - buffer->pos){
        sended_bytes = send(*socket_fd, buffer->pos, size_of_bucket, 0);
        if(sended_bytes < 0) {
            goto error;
        }
        received_bytes = recv(*socket_fd, return_code, 4, MSG_WAITALL);
        if (received_bytes < 0) {
            goto error;
        }
        if (return_code[0] != (uint8_t) 0xFF || return_code[1] != (uint8_t) 0x00 || return_code[2] != (uint8_t) 0xFF || return_code[3] != (uint8_t) 0x00){
            goto error;
        }
        buffer->pos += sended_bytes;
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

static void ngx_http_hercules_thread_sender_completion(ngx_event_t* ev){
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
    #ifdef THREAD_SENDER
    ngx_thread_task_t* task;
    ngx_http_hercules_thread_sender_ctx_t* ctx;
    ngx_buf_t* buffer;
    ngx_pool_t* pool = conf->pool;
    ngx_thread_pool_t* thread_pool = conf->thread_pool;
    ngx_queue_t* task_queue = conf->task_queue;

    /* copy buffer */
    size_t buffer_size = conf->buffer->pos - conf->buffer->start;
    if(buffer_size > 0){
        buffer = ngx_create_temp_buf(pool, buffer_size);
        if(buffer == NULL){
            return;
        }
        ngx_memcpy(buffer->start, conf->buffer->start, buffer_size);

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
    #endif
}

#endif

#ifdef EVENT_LOOP_SENDER
#endif