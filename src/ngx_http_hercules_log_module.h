#ifndef __NGX_HTTP_HERCULES
#define __NGX_HTTP_HERCULES
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event_openssl.h>
#include <endian.h>
#include <libhercules.h>
#include "ngx_http_hercules_log_struct.h"
#include "ngx_http_hercules_log_network.h"

#define HERCULES_LOG_BUFFER_SIZE 1024 * 1024 * 8
#define HERCULES_LOG_BUFFER_FLUSH_TIME 10 * 1000

#define STR_FROM_NGX_STR(variable, pool, value) \
  char* variable = ngx_palloc(pool, sizeof(char) * (value.len + 1)); \
  variable[value.len] = '\0'; \
  ngx_memcpy(variable, value.data, value.len);

static ngx_int_t ngx_http_hercules_handler(ngx_http_request_t* r);
static ngx_int_t ngx_http_hercules_postconf(ngx_conf_t* cf);
static void ngx_http_hercules_exit_process(ngx_cycle_t* cycle);
static void* ngx_http_hercules_create_conf(ngx_conf_t* cf);
static void ngx_http_hercules_flush_handler(ngx_event_t* ev);
static void ngx_http_hercules_flush_buffer(ngx_http_hercules_main_conf_t* conf, ngx_log_t* log);
static u_int ngx_http_hercules_event_host(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);
static u_int ngx_http_hercules_event_uri(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);
static u_int ngx_http_hercules_event_args(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);
static u_int ngx_http_hercules_event_status(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);
static u_int ngx_http_hercules_event_method(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);
static u_int ngx_http_hercules_event_proto(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);
static u_int ngx_http_hercules_event_req_headers(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);
static u_int ngx_http_hercules_event_res_headers(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);
static u_int ngx_http_hercules_event_counters(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);
static u_int ngx_http_hercules_event_connection(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);
static u_int ngx_http_hercules_event_request_id(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);
static u_int ngx_http_hercules_event_node(Event_pool* pool, List* root_container, ngx_http_request_t* r, ngx_http_hercules_main_conf_t* mcf);
#endif