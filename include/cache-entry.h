#ifndef CACHE_PROXY_CACHE_ENTRY
#define CACHE_PROXY_CACHE_ENTRY

#define _GNU_SOURCE

#include <pthread.h>
#include <stdatomic.h>

#define BLOCK_SIZE 4096

typedef struct cache_block {
    char data[BLOCK_SIZE];
    size_t used;
    struct cache_block *next;
} cache_block_t;

typedef struct {
    cache_block_t *first;
    cache_block_t *last;
    pthread_mutex_t list_mutex;

    atomic_size_t total_size;

    int completed;
    int canceled;
    pthread_mutex_t state_mutex;
    pthread_cond_t updated;

    int ref_cnt;
    pthread_spinlock_t ref_cnt_lock;
} cache_entry_t;

cache_entry_t *cache_entry_create();
void cache_entry_destroy(cache_entry_t *entry);

int cache_entry_append(cache_entry_t *entry, char *new_data, size_t size);

void cache_entry_set_completed(cache_entry_t *entry);
void cache_entry_set_canceled(cache_entry_t *entry);

void cache_entry_reference(cache_entry_t *entry);
void cache_entry_dereference(cache_entry_t *entry);

#endif /* CACHE_PROXY_CACHE_ENTRY */
