#ifndef CACHE_PROXY_CACHE_STORAGE
#define CACHE_PROXY_CACHE_STORAGE

#include <pthread.h>
#include <time.h>

#include "cache-entry.h"

#define MAP_SIZE            256
#define EXPIRY_TIME         (60 * 5)

typedef struct _node {
    char *request;
    cache_entry_t *response;
    struct _node *next;

    time_t put_time;
} node_t;

struct {
    node_t **map;
    pthread_mutex_t mutex;
} typedef cache_storage_t;

cache_storage_t *cache_storage_create();
void cache_storage_destroy(cache_storage_t *storage);

int cache_storage_put(cache_storage_t *storage, char *req, cache_entry_t *resp);
cache_entry_t *cache_storage_get(cache_storage_t *storage, char *req);

int cache_storage_remove(cache_storage_t *storage, char *req);
int cache_storage_clean(cache_storage_t *storage);

#endif /* CACHE_PROXY_CACHE_STORAGE */
