#include "ngx_http_hercules_log_module.h"

static ngx_int_t ngx_http_hercules_handler(ngx_http_request_t* r);
static ngx_int_t ngx_http_hercules_postconf(ngx_conf_t* cf);
static void ngx_http_hercules_exit_process(ngx_cycle_t* cycle);
static void* ngx_http_hercules_create_conf(ngx_conf_t* cf);
static void ngx_http_hercules_flush_handler(ngx_event_t* ev);
static void ngx_http_hercules_flush_buffer(ngx_http_hercules_main_conf_t* conf, ngx_log_t* log);
static inline ngx_int_t ngx_http_hercules_event_host(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);
static inline ngx_int_t ngx_http_hercules_event_uri(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);
static inline ngx_int_t ngx_http_hercules_event_args(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);
static inline ngx_int_t ngx_http_hercules_event_status(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);
static inline ngx_int_t ngx_http_hercules_event_method(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);
static inline ngx_int_t ngx_http_hercules_event_proto(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);
static inline ngx_int_t ngx_http_hercules_event_req_headers(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);
static inline ngx_int_t ngx_http_hercules_event_res_headers(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);
static inline ngx_int_t ngx_http_hercules_event_counters(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);
static inline ngx_int_t ngx_http_hercules_event_connection(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);
static inline ngx_int_t ngx_http_hercules_event_request_id(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);
static inline ngx_int_t ngx_http_hercules_event_node(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);

static ngx_http_module_t  ngx_http_hercules_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_hercules_postconf,            /* postconfiguration */

    ngx_http_hercules_create_conf,         /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_hercules_module = {
    NGX_MODULE_V1,
    &ngx_http_hercules_module_ctx,         /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_hercules_exit_process,        /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_hercules_handler(ngx_http_request_t *r){

    ngx_http_hercules_main_conf_t* mcf = ngx_http_get_module_main_conf(r, ngx_http_hercules_module);

    if(r->connection->local_sockaddr->sa_family == AF_UNIX){
        /* ignore unix servers */
        return NGX_OK;
    }
    
    uint8_t uuid[16];
    generate_uuid_v4(uuid);
    uint64_t timestamp = generate_current_timestamp();
    Event_pool pool;
    pool_init(&pool, r->pool);
    Event* event = event_create(&pool, 0x01, timestamp, uuid);

    /* container /NginxEvent is empty */

    /* /NginxEvent/time = Long*/
    container_add_tag_Long(&pool, event->payload, 4, "time", timestamp);

    /* /NginxEvent/host = String */
    if(ngx_http_hercules_event_host(&pool, event->payload, r, mcf) == NGX_ERROR){
        return NGX_ERROR;
    }

    /* /NginxEvent/uri = String */
    if(ngx_http_hercules_event_uri(&pool, event->payload, r, mcf) == NGX_ERROR){
        return NGX_ERROR;
    }

    /* /NginxEvent/args */
    if(ngx_http_hercules_event_args(&pool, event->payload, r, mcf) == NGX_ERROR){
        return NGX_ERROR;
    }
    
    /* /NginxEvent/status */
    if(ngx_http_hercules_event_status(&pool, event->payload, r, mcf) == NGX_ERROR){
        return NGX_ERROR;
    }

    /* /NginxEvent/method */
    if(ngx_http_hercules_event_method(&pool, event->payload, r, mcf) == NGX_ERROR){
        return NGX_ERROR;
    }

    /* /NginxEvent/proto */
    if(ngx_http_hercules_event_proto(&pool, event->payload, r, mcf) == NGX_ERROR){
        return NGX_ERROR;
    }

    /* /NginxEvent/req_headers */
    if(ngx_http_hercules_event_req_headers(&pool, event->payload, r, mcf) == NGX_ERROR){
        return NGX_ERROR;
    }

    /* /NginxEvent/res_headers */
    if(ngx_http_hercules_event_res_headers(&pool, event->payload, r, mcf) == NGX_ERROR){
        return NGX_ERROR;
    }

    /* /NginxEvent/upstream_status */
    /* /NginxEvent/upstream_addr */
    /* /NginxEvent/counters */
    if(ngx_http_hercules_event_counters(&pool, event->payload, r, mcf) == NGX_ERROR){
        return NGX_ERROR;
    }

    /* /NginxEvent/connection */
    if(ngx_http_hercules_event_connection(&pool, event->payload, r, mcf) == NGX_ERROR){
        return NGX_ERROR;
    }

    /* /NginxEvent/request_id */
    if(ngx_http_hercules_event_request_id(&pool, event->payload, r, mcf) == NGX_ERROR){
        return NGX_ERROR;
    }

    /* /NginxEvent/node */
    if(ngx_http_hercules_event_node(&pool, event->payload, r, mcf) == NGX_ERROR){
        return NGX_ERROR;
    }

    /* container /NginxEvent is full */

    Event_binary* event_binary = event_to_bin(event);

    //event_free(event);

    size_t message_length = sizeof(uint32_t) + event_binary->size;
    uint32_t be_event_size = htobe32((uint32_t) event_binary->size);
    
    if((size_t) (mcf->buffer->end - mcf->buffer->pos) < message_length){
        if(mcf->event->timer_set){
            ngx_event_del_timer(mcf->event);
        }
        ngx_http_hercules_flush_buffer(mcf, r->connection->log);
    }

    u_char* pos = mcf->buffer->pos;
    ngx_memcpy(pos, &be_event_size, sizeof(be_event_size));
    ngx_memcpy(pos, event_binary->value, event_binary->size);
    pos += event_binary->size;
    mcf->buffer->pos = pos;

    mcf->event->log = ngx_cycle->log;
    if(!mcf->event->timer_set){
        ngx_event_add_timer(mcf->event, mcf->flush);
    }

    return NGX_OK;
}

static void* ngx_http_hercules_create_conf(ngx_conf_t* cf){
    ngx_http_hercules_main_conf_t* mcf;
    
    mcf = ngx_palloc(cf->pool, sizeof(ngx_http_hercules_main_conf_t));
    if(mcf == NULL){
        return NULL;
    }

    mcf->flush = HERCULES_LOG_BUFFER_FLUSH_TIME;
    mcf->event = ngx_pcalloc(cf->pool, sizeof(ngx_event_t));
    if(mcf->event == NULL){
        return NULL;
    }
    mcf->event->cancelable = 1;
    mcf->event->handler = ngx_http_hercules_flush_handler;
    mcf->event->data = mcf;
    mcf->event->log = &cf->cycle->new_log;

    mcf->pool = cf->pool;

    mcf->buffer = ngx_create_temp_buf(cf->pool, HERCULES_LOG_BUFFER_SIZE);
#ifdef THREAD_SENDER
    mcf->task_queue = ngx_palloc(cf->pool, sizeof(ngx_queue_t));
    mcf->sockets = ngx_palloc(cf->pool, sizeof(ngx_queue_t));
    ngx_str_t hercules_thread_pool_name = ngx_string(HERCULES_THREAD_POOL_NAME);
    ngx_queue_init(mcf->task_queue);
    ngx_queue_init(mcf->sockets);
    for(uint8_t i = 0; i < HERCULES_LOG_MAX_SOCKET_SIZE; ++i){
        ngx_http_hercules_thread_queue_socket_t* s = ngx_palloc(mcf->pool, sizeof(ngx_http_hercules_thread_queue_socket_t));
        s->socket = -1;
        ngx_queue_insert_tail(mcf->sockets, &s->queue);
    }
    mcf->thread_pool = ngx_thread_pool_add(cf, &hercules_thread_pool_name);
#endif
    return mcf;
}

static ngx_int_t ngx_http_hercules_postconf(ngx_conf_t *cf){
    ngx_http_core_main_conf_t*     cmcf;
    ngx_http_hercules_main_conf_t* mcf;
    ngx_http_handler_pt*           h;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_hercules_module);

    ngx_str_t s_node_name = ngx_string("node_name");
    mcf->node_var_inx = ngx_http_get_variable_index(cf, &s_node_name);

    mcf->log = cf->log;

#ifdef THREAD_SENDER
#endif

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_hercules_handler;

    return NGX_OK;
}

static void ngx_http_hercules_exit_process(ngx_cycle_t *cycle){
    if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE){
        return;
    }
    #ifdef THREAD_SENDER
    ngx_http_hercules_main_conf_t* mcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_hercules_module);
    if(mcf == NULL){
        return;
    }
    ngx_http_hercules_send_metrics(mcf, 1);
    #endif
}

static void ngx_http_hercules_flush_buffer(ngx_http_hercules_main_conf_t* conf, ngx_log_t* log){
    #ifdef THREAD_SENDER
    ngx_http_hercules_send_metrics(conf, 0);
    #endif
}

static void ngx_http_hercules_flush_handler(ngx_event_t* ev){
    ngx_log_error(NGX_LOG_INFO, ev->log, 0, "flush_handler");
    ngx_http_hercules_main_conf_t* conf = (ngx_http_hercules_main_conf_t*) ev->data;
    ngx_http_hercules_flush_buffer(conf, ev->log);
}

static inline ngx_int_t ngx_http_hercules_event_host(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf){
    if(r->headers_in.host != NULL){
        STR_FROM_NGX_STR(s_host, r->pool, r->headers_in.host->value);
        container_add_tag_String(pool, root_container, 4, "host", s_host);
    } else {
        container_add_tag_String(pool, root_container, 4, "host", "");
    }
    return NGX_OK;
}

static inline ngx_int_t ngx_http_hercules_event_uri(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf){
    STR_FROM_NGX_STR(s_uri, r->pool, r->uri);
    container_add_tag_String(pool, root_container, 3, "uri", s_uri);
    return NGX_OK;
}

static inline ngx_int_t ngx_http_hercules_event_args(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf){
    Vector* vector_args = (Vector*) container_add_tag_Vector(pool, root_container, CONTAINER, 4, "args")->value;
    char* key = ngx_palloc(r->pool, sizeof(char) * (r->args.len + 1));
    size_t key_inx = 0;
    char* value = ngx_palloc(r->pool, sizeof(char) * (r->args.len + 1));
    size_t value_inx = 0;
    if(key == NULL || value == NULL){
        return NGX_ERROR;
    }

    uint8_t key_full = 0;
    uint8_t value_full = 0;
    
    /* WTF?! Need refactoring for this loop */
    for(size_t i = 0; i < r->args.len; ++i){
        char buffer = r->args.data[i];
        if(buffer == '='){
            key_full = 1;
        }
        if(buffer == '&'){
            key_full = 1;
            value_full = 1;
        }
        if(!key_full && buffer != '=' && buffer != '&'){
            key[key_inx++] = buffer;
        }
        if(key_full && !value_full && buffer != '=' && buffer != '&'){
            value[value_inx++] = buffer;
        }
        if(!(key_full && value_full) && r->args.len - 1 != i){
            continue;
        }

        /* if key exist */
        if(key_inx > 0){
    /* /NginxEvent/args/<container> */
            List* container_args = vector_add_Container(pool, vector_args);
            key[key_inx] = '\0';
            value[value_inx] = '\0';
            container_add_tag_String(pool, container_args, 1, "k", key);
            container_add_tag_String(pool, container_args, 1, "v", value);
        }
        key_full = 0;
        value_full = 0;
        key_inx = 0;
        value_inx = 0;
    }
    return NGX_OK;
}

static inline ngx_int_t ngx_http_hercules_event_status(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf){
    container_add_tag_Short(pool, root_container, 6, "status", (int16_t) r->headers_out.status);
    return NGX_OK;
}

static inline ngx_int_t ngx_http_hercules_event_method(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf){
    uint8_t b_method;
    switch(r->method){
        case NGX_HTTP_HEAD:
            b_method = 0x00;
            break;
        case NGX_HTTP_GET:
            b_method = 0x01;
            break;
        case NGX_HTTP_POST:
            b_method = 0x02;
            break;
        case NGX_HTTP_PUT:
            b_method = 0x03;
            break;
        case NGX_HTTP_DELETE:
            b_method = 0x04;
            break;
        /* 0x05 - CONNECT */
        case NGX_HTTP_OPTIONS:
            b_method = 0x06;
            break;
        case NGX_HTTP_TRACE:
            b_method = 0x07;
            break;
        case NGX_HTTP_PATCH:
            b_method = 0x08;
            break;
        case NGX_HTTP_MKCOL:
            b_method = 0x09;
            break;
        case NGX_HTTP_COPY:
            b_method = 0x0a;
            break;
        case NGX_HTTP_MOVE:
            b_method = 0x0b;
            break;
        case NGX_HTTP_PROPFIND:
            b_method = 0x0c;
            break;
        case NGX_HTTP_PROPPATCH:
            b_method = 0x0d;
            break;
        case NGX_HTTP_LOCK:
            b_method = 0x0e;
            break;
        case NGX_HTTP_UNLOCK:
            b_method = 0x0f;
            break;
        default:
            b_method = 0xFF;
            break;
    }
    container_add_tag_Byte(pool, root_container, 6, "method", b_method);
    return NGX_OK;
}

static inline ngx_int_t ngx_http_hercules_event_proto(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf){
    STR_FROM_NGX_STR(s_proto, r->pool, r->http_protocol);
    container_add_tag_String(pool, root_container, 5, "proto", s_proto);
    return NGX_OK;
}

static inline ngx_int_t ngx_http_hercules_event_req_headers(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf){
    Vector* vector_req_headers = (Vector*) container_add_tag_Vector(pool, root_container, CONTAINER, 11, "req_headers")->value;
    if(r->headers_in.headers.nalloc == 0){
        return NGX_OK;
    }
    ngx_list_part_t* req_headers_part = &r->headers_in.headers.part;
    while(1){
        for(size_t i = 0; i < (size_t) req_headers_part->nelts; ++i){
            ngx_table_elt_t* header = ((ngx_table_elt_t*) req_headers_part->elts) + i;
            if(header == NULL){
                continue;
            }
            List* container_req_header = vector_add_Container(pool, vector_req_headers);
            STR_FROM_NGX_STR(s_req_key, r->pool, header->key);
            for(size_t key_i = 0; key_i < header->key.len; ++key_i){
                s_req_key[key_i] = ngx_tolower(s_req_key[key_i]);
            }
            STR_FROM_NGX_STR(s_req_value, r->pool, header->value);
            container_add_tag_String(pool, container_req_header, 1, "k", s_req_key);
            container_add_tag_String(pool, container_req_header, 1, "v", s_req_value);
        }
        
        req_headers_part = req_headers_part->next;
        if(req_headers_part == NULL){
            break;
        }
    }
    return NGX_OK;
}

static inline ngx_int_t ngx_http_hercules_event_res_headers(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf){
    Vector* vector_res_headers = (Vector*) container_add_tag_Vector(pool, root_container, CONTAINER, 11, "res_headers")->value;
    /* /NginxEvent/res_headers/<content-type> */
    if(r->headers_out.content_type.data != NULL){
        List* container_content_type = vector_add_Container(pool, vector_res_headers);
        container_add_tag_String(pool, container_content_type, 1, "k", "content-type");
        STR_FROM_NGX_STR(s_value_content_type, r->pool, r->headers_out.content_type);
        container_add_tag_String(pool, container_content_type, 1, "v", s_value_content_type);
    }
    /* /NginxEvent/res_headers/<content_length> */
    if(r->headers_out.content_length != NULL && r->headers_out.content_length->value.data != NULL){
        List* container_content_length = vector_add_Container(pool, vector_res_headers);
        container_add_tag_String(pool, container_content_length, 1, "k", "content-length");
        STR_FROM_NGX_STR(s_value_content_length, r->pool, r->headers_out.content_length->value);
        container_add_tag_String(pool, container_content_length, 1, "v", s_value_content_length);
    }
    /* /NginxEvent/res_headers/<other> */

    ngx_list_part_t* res_headers_part = &r->headers_out.headers.part;
    while(1){
        for(size_t i = 0; i < (size_t) res_headers_part->nelts; ++i){
            ngx_table_elt_t* header = ((ngx_table_elt_t*) res_headers_part->elts) + i;
            if(header == NULL){
                continue;
            }
            STR_FROM_NGX_STR(s_res_key, r->pool, header->key);
            for(size_t key_i = 0; key_i < header->key.len; ++key_i){
                s_res_key[key_i] = ngx_tolower(s_res_key[key_i]);
            }
            if(ngx_strcmp(s_res_key, "x-singular-backend") == 0 ||
             ngx_strcmp(s_res_key, "x-kontur-trace-id") == 0 ){
                STR_FROM_NGX_STR(s_res_value, r->pool, header->value);
                List* container_res_header = vector_add_Container(pool, vector_res_headers);
                container_add_tag_String(pool, container_res_header, 1, "k", s_res_key);
                container_add_tag_String(pool, container_res_header, 1, "v", s_res_value);
            }
        }

        res_headers_part = res_headers_part->next;
        if(res_headers_part == NULL){
            break;
        }
    }
    return NGX_OK;
}

static inline ngx_int_t ngx_http_hercules_event_counters(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf){
    /* /NginxEvent/upstream_status */
    Vector* vector_upstream_status = (Vector*) container_add_tag_Vector(pool, root_container, SHORT, 15, "upstream_status")->value;

    /* /NginxEvent/upstream_addr */
    Vector* vector_upstream_addr = (Vector*) container_add_tag_Vector(pool, root_container, STRING, 13, "upstream_addr")->value;

    /* /NginxEvent/counters */
    List* container_counters = (List*) container_add_tag_Container(pool, root_container, 8, "counters")->value;

    /* /NginxEvent/counters/req_len */
    container_add_tag_Integer(pool, container_counters, 7, "req_len", (int32_t) r->request_length);

    /* /NginxEvent/counters/upstream_connect_time */
    Vector* vector_upstream_connect_time = (Vector*) container_add_tag_Vector(pool, container_counters, LONG, 21, "upstream_connect_time")->value;

    /* /NginxEvent/counters/upstream_req_bytes */
    Vector* vector_upstream_req_bytes = (Vector*) container_add_tag_Vector(pool, container_counters, LONG, 18, "upstream_req_bytes")->value;

    /* /NginxEvent/counters/upstream_res_bytes */
    Vector* vector_upstream_res_bytes = (Vector*) container_add_tag_Vector(pool, container_counters, LONG, 18, "upstream_res_bytes")->value;

    /* /NginxEvent/counters/upstream_res_header_time */
    Vector* vector_upstream_res_header_time = (Vector*) container_add_tag_Vector(pool, container_counters, LONG, 24, "upstream_res_header_time")->value;

    /* /NginxEvent/counters/upstream_res_len */
    Vector* vector_upstream_res_len = (Vector*) container_add_tag_Vector(pool, container_counters, LONG, 16, "upstream_res_len")->value;

    /* /NginxEvent/counters/upstream_res_time */
    Vector* vector_upstream_res_time = (Vector*) container_add_tag_Vector(pool, container_counters, LONG, 17, "upstream_res_time")->value;
    
    if(r->upstream_states != NULL){
        ngx_http_upstream_state_t* upstream_state = r->upstream_states->elts;
        for (size_t i = 0; i != (size_t) r->upstream_states->nelts; ++i){
            vector_add_Short(pool, vector_upstream_status, (int16_t) upstream_state[i].status);
            if(upstream_state[i].peer != NULL){
                char* string_upstream_addr = ngx_palloc(r->pool, (sizeof(char) * upstream_state[i].peer->len) + 1);
                string_upstream_addr[upstream_state[i].peer->len] = '\0';
                ngx_memcpy(string_upstream_addr, upstream_state[i].peer->data, upstream_state[i].peer->len);
                vector_add_String(pool, vector_upstream_addr, string_upstream_addr);
            }
            vector_add_Long(pool, vector_upstream_connect_time, (int64_t) upstream_state[i].connect_time);
            vector_add_Long(pool, vector_upstream_req_bytes, (int64_t) upstream_state[i].bytes_sent);
            vector_add_Long(pool, vector_upstream_res_bytes, (int64_t) upstream_state[i].bytes_received);
            vector_add_Long(pool, vector_upstream_res_header_time, (int64_t) upstream_state[i].header_time);
            vector_add_Long(pool, vector_upstream_res_len, (int64_t) upstream_state[i].response_length);
            vector_add_Long(pool, vector_upstream_res_time, (int64_t) upstream_state[i].response_time);
        }
    }
    
    /* /NginxEvent/counters/res_bytes */
    container_add_tag_Long(pool, container_counters, 9, "res_bytes", (int64_t) r->connection->sent);

    /* /NginxEvent/counters/full_time */
    ngx_time_t* tp_full_time = ngx_timeofday();
    ngx_msec_int_t ms_full_time = (ngx_msec_int_t) ((tp_full_time->sec - r->start_sec) * 1000 + (tp_full_time->msec - r->start_msec));
    ms_full_time = ngx_max(ms_full_time, 0);
    container_add_tag_Long(pool, container_counters, 9, "full_time", (int64_t) ms_full_time);

    return NGX_OK;
}

static inline ngx_int_t ngx_http_hercules_event_connection(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf){
    List* container_connection = (List*) container_add_tag_Container(pool, root_container, 10, "connection")->value;

    /* /NginxEvent/connection/port */
    container_add_tag_Short(pool, container_connection, 4, "port", (int16_t) ngx_inet_get_port(r->connection->local_sockaddr));

    /* /NginxEvent/connection/addr */
    ngx_str_t  connection_addr;
    u_char     addr[NGX_SOCKADDR_STRLEN];
    connection_addr.len = NGX_SOCKADDR_STRLEN;
    connection_addr.data = addr;
    char string_connection_addr[46];
    if (ngx_connection_local_sockaddr(r->connection, &connection_addr, 0) == NGX_OK) {
        string_connection_addr[connection_addr.len] = '\0';
        ngx_memcpy(string_connection_addr, connection_addr.data, connection_addr.len);
        container_add_tag_String(pool, container_connection, 4, "addr", "");
    }

    /* /NginxEvent/connection/client_ip */
    char string_client_addr[46];
    ngx_memcpy(string_client_addr, (char*) r->connection->addr_text.data, r->connection->addr_text.len);
    string_client_addr[r->connection->addr_text.len] = '\0';
    container_add_tag_String(pool, container_connection, 9, "client_ip", string_client_addr);

    /* /NginxEvent/connection/client_port */
    container_add_tag_Short(pool, container_connection, 11, "client_port", (int16_t) ngx_inet_get_port(r->connection->sockaddr));

    
    if(r->connection->ssl){
        /* /NginxEvent/connection/tls_verison */
        container_add_tag_String(pool, container_connection, 11, "tls_version", (char*) SSL_get_version(r->connection->ssl->connection));

        /* /NginxEvent/connection/cipher */
        container_add_tag_String(pool, container_connection, 6, "cipher", (char*) SSL_get_cipher_name(r->connection->ssl->connection));
    }

    /* /NginxEvent/connection/scheme */
    STR_FROM_NGX_STR(s_scheme, r->pool, r->schema);
    container_add_tag_String(pool, container_connection, 6, "scheme", s_scheme);

    /* /NginxEvent/connection/connection */
    container_add_tag_Long(pool, container_connection, 10, "connection", (int64_t) r->connection->number);

    return NGX_OK;
}

static inline ngx_int_t ngx_http_hercules_event_request_id(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf){
    u_char random_bytes[16];
    u_char s_request_id[33];
    s_request_id[32] = '\0';
#if !(NGX_LINUX)
    /* libcrypto call (openssl) */
    if (RAND_bytes(random_bytes, 16) == 1) {
#endif
#if (NGX_LINUX)
    /* getrandom() system call. /dev/urandom as source */
    /* required linux kernel >= 3.17 and glibc >= 2.25 */
    /* if(getrandom(random_bytes, 16, 0)) { */
    /* centos - kernel 3.10 */

#ifndef USE_RDSEED
    /* simple rand */
    if(1){
        random_bytes[0] = rand() % 256;
        random_bytes[1] = rand() % 256;
        random_bytes[2] = rand() % 256;
        random_bytes[3] = rand() % 256;
        random_bytes[4] = rand() % 256;
        random_bytes[5] = rand() % 256;
        random_bytes[6] = rand() % 256;
        random_bytes[7] = rand() % 256;
        random_bytes[8] = rand() % 256;
        random_bytes[9] = rand() % 256;
        random_bytes[10] = rand() % 256;
        random_bytes[11] = rand() % 256;
        random_bytes[12] = rand() % 256;
        random_bytes[13] = rand() % 256;
        random_bytes[14] = rand() % 256;
        random_bytes[15] = rand() % 256;
#endif
#ifdef USE_RDSEED
    if(1){
        while(_rdseed64_step((uint64_t*) random_bytes) != 1){}
        while(_rdseed64_step((uint64_t*) (random_bytes+8)) != 1){}
#endif
#endif
        ngx_hex_dump(s_request_id, random_bytes, 16);
        container_add_tag_String(pool, root_container, 10, "request_id", (char*) s_request_id);
    }

    return NGX_OK;
}

static inline ngx_int_t ngx_http_hercules_event_node(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf){
    ngx_http_variable_value_t* var_node_name = ngx_http_get_indexed_variable(r, mcf->node_var_inx);
    char* s_node_name = ngx_palloc(r->pool, sizeof(char) * (var_node_name->len + 1));
    s_node_name[var_node_name->len] = '\0';
    ngx_memcpy(s_node_name, var_node_name->data, var_node_name->len);
    container_add_tag_String(pool, root_container, 4, "node", s_node_name);
    return NGX_OK;
}