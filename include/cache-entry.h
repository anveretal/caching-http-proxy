#ifndef CACHE_PROXY_CACHE_ENTRY
#define CACHE_PROXY_CACHE_ENTRY

#define _GNU_SOURCE

#include <pthread.h>
#include <stdatomic.h>

struct {
    char *buf;
    size_t size;
    size_t capacity;

    int completed;
    int canceled;
    pthread_mutex_t mutex;
    pthread_cond_t updated;

    int ref_cnt;
    pthread_spinlock_t ref_cnt_lock;
} typedef cache_entry_t;

cache_entry_t *cache_entry_create();
void cache_entry_destroy(cache_entry_t *entry);
int cache_entry_append(cache_entry_t *entry, char *new_data, size_t size);

void cache_entry_set_completed(cache_entry_t *entry);
void cache_entry_set_canceled(cache_entry_t *entry);

void cache_entry_reference(cache_entry_t *entry);
void cache_entry_dereference(cache_entry_t *entry);

#endif /* CACHE_PROXY_CACHE_ENTRY */
