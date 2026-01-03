#include <stdlib.h>
#include <string.h>

#include "cache-entry.h"
#include "logger.h"

#define CHUNK_SIZE          1024

cache_entry_t *cache_entry_create() {
    cache_entry_t *entry = calloc(1, sizeof(*entry));
    if (!entry) return NULL;
    entry->ref_cnt = 1;
    pthread_mutex_init(&entry->mutex, NULL);
    pthread_cond_init(&entry->updated, NULL);
    pthread_spin_init(&entry->ref_cnt_lock, 0);

    log_debug("cache_entry_create: created %p", entry);

    return entry;
}

void cache_entry_destroy(cache_entry_t *entry) {
    if (!entry) return;
    free(entry->buf);
    entry->buf = NULL;
    pthread_mutex_destroy(&entry->mutex);
    pthread_cond_destroy(&entry->updated);
    pthread_spin_destroy(&entry->ref_cnt_lock);

    log_debug("cache_entry_destroy: destroyed %p", entry);
    free(entry);
}

int cache_entry_append(cache_entry_t *entry, char *new_data, size_t size) {
    if (!entry || !new_data) return 0;

    pthread_mutex_lock(&entry->mutex);

    size_t new_size = entry->size + size;
    if (entry->capacity < new_size) {
        size_t new_capacity = new_size + CHUNK_SIZE;
        char *new_buf = realloc(entry->buf, new_capacity);
        if (new_buf == NULL) {
            pthread_mutex_unlock(&entry->mutex);
            return -1;
        }
        entry->buf = new_buf;
        entry->capacity = new_capacity;
    }

    memcpy(entry->buf + entry->size, new_data, size);
    entry->size += size;

    pthread_cond_broadcast(&entry->updated);
    pthread_mutex_unlock(&entry->mutex);

    return 0;
}



void cache_entry_set_completed(cache_entry_t *entry) {
    if (!entry) return;
    pthread_mutex_lock(&entry->mutex);
    entry->completed = 1;
    pthread_cond_broadcast(&entry->updated);
    pthread_mutex_unlock(&entry->mutex);
}

void cache_entry_set_canceled(cache_entry_t *entry) {
    if (!entry) return;
    pthread_mutex_lock(&entry->mutex);
    entry->canceled = 1;
    pthread_cond_broadcast(&entry->updated);
    pthread_mutex_unlock(&entry->mutex);
}



void cache_entry_reference(cache_entry_t *entry) {
    if (!entry) return;
    pthread_spin_lock(&entry->ref_cnt_lock);
    entry->ref_cnt++;
    pthread_spin_unlock(&entry->ref_cnt_lock);
}

void cache_entry_dereference(cache_entry_t *entry) {
    if (!entry) return;
    pthread_spin_lock(&entry->ref_cnt_lock);
    entry->ref_cnt--;
    if (entry->ref_cnt == 0) {
        pthread_spin_unlock(&entry->ref_cnt_lock);
        cache_entry_destroy(entry);
        return;
    }
    pthread_spin_unlock(&entry->ref_cnt_lock);
}
