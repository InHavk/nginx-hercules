#include "ngx_http_hercules_log_network.h"

#ifdef THREAD_SENDER
static void ngx_http_hercules_thread_sender(void* data, ngx_log_t* log){
    /* executed in thread */
    ngx_http_hercules_thread_sender_ctx_t* ctx = data;

    struct sockaddr_in server_addr;
    int logic_true = 1;
    struct timeval send_timeout;
    send_timeout.tv_sec = HERCULES_THREAD_SEND_TIMEOUT;
    send_timeout.tv_usec = 0;
    static __thread int socket_fd = -1;

    for(uint8_t i = 0; i < ctx->buckets->nelts; ++i){
        ngx_http_hercules_thread_sender_bucket_ctx_t* bucket = ((ngx_http_hercules_thread_sender_bucket_ctx_t*) ctx->buckets->elts) + i;
        uint8_t retries = 0;
        bucket->counter++;
reconnect:
        if(socket_fd < 1){
            socket_fd = socket(AF_INET, SOCK_STREAM, 0);
            if(socket_fd < 0){
                goto error;
            }
            if(setsockopt(socket_fd, SOL_SOCKET, SO_KEEPALIVE, &logic_true, sizeof(logic_true)) < 0){
                goto error;
            }
            if(setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout)) < 0){
                goto error;
            }
            ngx_memzero(&server_addr, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(HERCULES_SENDER_POST);
            inet_pton(AF_INET, HERCULES_SENDER_HOST, &server_addr.sin_addr);
            if(connect(socket_fd, &server_addr, sizeof(server_addr)) < 0){
                goto error;
            }
        }
    
        ssize_t sended_bytes = 0;
        size_t size_of_bucket = bucket->buffer->end - bucket->buffer->pos;
        while(size_of_bucket > 0){
            sended_bytes = send(socket_fd, bucket->buffer->pos, size_of_bucket, 0);
            if(sended_bytes < 0) {
                goto error;
            }
            bucket->buffer->pos += sended_bytes;
            size_of_bucket = bucket->buffer->end - bucket->buffer->pos;
        }

        bucket->status = 1;
        continue;
error:
        if(socket_fd >= 0){
            close(socket_fd);
            socket_fd = -2;
        }
        bucket->buffer->pos = bucket->buffer->start;
        if(retries == 0){
            retries++;
            goto reconnect;
        }
        continue;
    }

}

static void ngx_http_hercules_thread_sender_completion(ngx_event_t* ev){
    ngx_http_hercules_thread_sender_ctx_t* ctx = ev->data;
    ngx_pool_t* pool = ctx->conf->pool;
    ngx_thread_task_t* task = ctx->task;
    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "ngx_http_hercules_thread_sender_completion");

    for(uint8_t i = 0; i < ctx->buckets->nelts; ++i){
        ngx_http_hercules_thread_sender_bucket_ctx_t* bucket = ((ngx_http_hercules_thread_sender_bucket_ctx_t*) ctx->buckets->elts) + i;
        if(bucket->status == 0 && bucket->counter < HERCULES_THREAD_RESEND_COUNTER){
            /* resend bucket */
            ngx_http_hercules_thread_sender_bucket_ctx_t* bucket_new = ngx_array_push(ctx->conf->buckets_for_resend);
            bucket_new->buffer = bucket->buffer;
            bucket_new->counter = bucket->counter;
            bucket_new->status = bucket->status;
        } else {
            /* bucket sended or counter more than HERCULES_THREAD_RESEND_COUNTER */
            ngx_pfree(pool, bucket->buffer->start);
            ngx_pfree(pool, bucket->buffer);
        }
    }
    ngx_array_destroy(ctx->buckets);
    ngx_pfree(pool, task);
    if(ctx->conf->buckets_for_resend->nelts > 0 && !ctx->conf->event->timer_set){
        ngx_event_add_timer(ctx->conf->event, ctx->conf->flush);
    }
    
}

static void ngx_http_hercules_send_metrics(ngx_http_hercules_main_conf_t* conf, u_int8_t direct){
    #ifdef THREAD_SENDER
    ngx_thread_task_t* task;
    ngx_http_hercules_thread_sender_ctx_t* ctx;
    ngx_buf_t* buffer;
    ngx_pool_t* pool = conf->pool;
    ngx_thread_pool_t* thread_pool = conf->thread_pool;
    ngx_array_t* buckets_for_resend = conf->buckets_for_resend;

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
        ctx = ngx_palloc(conf->pool, sizeof(ngx_http_hercules_thread_sender_ctx_t));
    }

    ctx->conf = conf;
    ctx->task = task;

    /* copy buffer */
    size_t buffer_size = conf->buffer->pos - conf->buffer->start;
    buffer = ngx_create_temp_buf(pool, buffer_size);
    if(buffer == NULL){
        if(!direct){
            ngx_pfree(pool, task);
        }
        return;
    }
    ngx_memcpy(buffer->start, conf->buffer->start, buffer_size);

    /* reset buffer */
    conf->buffer->pos = conf->buffer->start;

    /* create list for resend if is Null */
    if(buckets_for_resend == NULL){
        buckets_for_resend = ngx_array_create(pool, HERCULES_THREAD_RESEND_BUCKETS_SIZE, sizeof(ngx_http_hercules_thread_sender_bucket_ctx_t));
    }

    /* create bucket for buffer */
    ngx_http_hercules_thread_sender_bucket_ctx_t* bucket = ngx_array_push(buckets_for_resend);
    bucket->counter = 0;
    bucket->status = 0;
    bucket->buffer = buffer;

    /* create new list of buffers */
    ctx->buckets = buckets_for_resend;
    conf->buckets_for_resend = ngx_array_create(pool, HERCULES_THREAD_RESEND_BUCKETS_SIZE, sizeof(ngx_http_hercules_thread_sender_bucket_ctx_t));

    /* set task handlers and push it into thread pool */
    if(!direct){
        task->handler = ngx_http_hercules_thread_sender;
        task->event.handler = ngx_http_hercules_thread_sender_completion;
        task->event.data = ctx;
        ngx_thread_task_post(thread_pool, task);
    } else {
        ngx_http_hercules_thread_sender(ctx, NULL);
    }
    
    #endif

    #ifdef EVENT_LOOP_SENDER
    #endif
}

#endif

#ifdef EVENT_LOOP_SENDER

#endif