#ifndef CACHE_PROXY_PROXY
#define CACHE_PROXY_PROXY

#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>

#include "cache-storage.h"
#include "threadpool.h"

typedef struct {
    int server_socket;
    int running;
    cache_storage_t *cache;
    thread_pool_t *threadpool;
} proxy_t;

proxy_t *proxy_create(cache_storage_t *cache, thread_pool_t *threadpool);
void proxy_destroy(proxy_t *proxy);

int proxy_start(proxy_t *proxy);

#endif /* CACHE_PROXY_PROXY */
