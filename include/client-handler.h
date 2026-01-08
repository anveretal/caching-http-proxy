#ifndef CACHE_PROXY_CLIENT_HANDLER
#define CACHE_PROXY_CLIENT_HANDLER

#include "cache-storage.h"
#include "picohttpparser.h"

#define TIMEOUT             10000
#define MAX_REQ_SIZE        8192
#define MAX_NUM_HEADERS     20
#define READ_BUF_LEN        4096

typedef struct phr_header phr_header_t;

typedef struct {
    const char *method;
    const char *path;
    phr_header_t headers[MAX_NUM_HEADERS];
    size_t method_len;
    size_t path_len;
    size_t num_headers;
    int minor_version;
} req_parse_t;

typedef struct {
    int minor_version;
    int status;
    const char *msg;
    size_t msg_len;
    phr_header_t headers[MAX_NUM_HEADERS];
    size_t num_headers;
} resp_parse_t;

typedef struct {
    int sock_to_client;
    cache_storage_t *cache;
} client_handler_args_t;

void client_handler_init();
void client_handler_fini();

void handle_client(void *args);

#endif /* CACHE_PROXY_CLIENT_HANDLER */
