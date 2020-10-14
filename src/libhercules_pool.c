#include "pool.h"
#include <ngx_core.h>

#define DISPOSABLE_POOL_SIZE 1024*64

typedef struct {
    void* start;
    void* end;
    void* pos;
    size_t size;
} Pool_Optional;

void* event_pool_alloc(Event_pool* pool, size_t size){
    if(size <= ((Pool_Optional*) pool->optional)->size){
        void* allocated = ((Pool_Optional*) pool->optional)->pos;
        ((Pool_Optional*) pool->optional)->pos += size;
        ((Pool_Optional*) pool->optional)->size -= size;
        return allocated;
    } else {
        return ngx_palloc((ngx_pool_t*) pool->pool, size);
    }
}

void* event_pool_realloc(Event_pool* pool, void* obj, size_t size, size_t prev_size){
    void* new = ngx_palloc((ngx_pool_t*) pool->pool, size);
    ngx_memcpy(new, obj, prev_size);
    ngx_pfree((ngx_pool_t*) pool->pool, obj);
    return new;
}

void  event_pool_free(Event_pool* pool, void* obj){
    
}

void  event_pool_force_free(Event_pool* pool, void* obj){
    if(obj >= ((Pool_Optional*) pool->optional)->start && obj < ((Pool_Optional*) pool->optional)->end){
        return
    } else {
        ngx_pfree((ngx_pool_t*) pool->pool, obj);
    }
}

void  event_pool_init(struct event_pool* pool, void* args){
    pool->pool = args;
    pool->optional = ngx_palloc((ngx_pool_t*) pool->pool, sizeof(Pool_Optional));
    ((Pool_Optional*) pool->optional)->start = ngx_palloc((ngx_pool_t*) pool->pool, DISPOSABLE_POOL_SIZE);
    ((Pool_Optional*) pool->optional)->pos = ((Pool_Optional*) pool->optional)->start;
    ((Pool_Optional*) pool->optional)->end = ((Pool_Optional*) pool->optional)->start + DISPOSABLE_POOL_SIZE;
    ((Pool_Optional*) pool->optional)->size = DISPOSABLE_POOL_SIZE;
}

void  event_pool_destroy(struct event_pool* pool){

}
