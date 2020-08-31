#include "pool.h"
#include <ngx_core.h>

void* event_pool_alloc(Event_pool* pool, size_t size){
    return ngx_palloc((ngx_pool_t*) pool->pool, size);
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
    ngx_pfree((ngx_pool_t*) pool->pool, obj);
}
void  event_pool_init(struct event_pool* pool){

}
void  event_pool_destroy(struct event_pool* pool){

}
