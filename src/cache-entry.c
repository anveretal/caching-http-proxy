#include <stdlib.h>
#include <string.h>

#include "cache-entry.h"
#include "logger.h"



cache_entry_t *cache_entry_create() {
    cache_entry_t *entry = calloc(1, sizeof(*entry));
    if (!entry) return NULL;

    entry->first = NULL;
    entry->last = NULL;
    atomic_init(&entry->total_size, 0);

    entry->completed = 0;
    entry->canceled = 0;

    entry->ref_cnt = 1;
    pthread_mutex_init(&entry->list_mutex, NULL);
    pthread_mutex_init(&entry->state_mutex, NULL);
    pthread_cond_init(&entry->updated, NULL);
    pthread_spin_init(&entry->ref_cnt_lock, 0);

    log_debug("cache_entry_create: created %p", entry);

    return entry;
}

void cache_entry_destroy(cache_entry_t *entry) {
    if (!entry) return;

    cache_block_t *current = entry->first;
    while (current) {
        cache_block_t *next = current->next;
        free(current);
        current = next;
    }

    pthread_mutex_destroy(&entry->list_mutex);
    pthread_mutex_destroy(&entry->state_mutex);
    pthread_cond_destroy(&entry->updated);
    pthread_spin_destroy(&entry->ref_cnt_lock);

    log_debug("cache_entry_destroy: destroyed %p", entry);
    free(entry);
}



int cache_entry_append(cache_entry_t *entry, char *new_data, size_t size) {
    if (!entry || !new_data) return 0;

    size_t remaining = size;
    size_t offset = 0;

    while(remaining > 0) {
        size_t to_copy = remaining > BLOCK_SIZE ? BLOCK_SIZE : remaining;

        cache_block_t *new_block = malloc(sizeof(cache_block_t));
        if (!new_block) return -1;

        memcpy(new_block->data, new_data + offset, to_copy);
        new_block->used = to_copy;
        new_block->next = NULL;

        pthread_mutex_lock(&entry->list_mutex);
        if (entry->last) {
            entry->last->next = new_block;
        } else {
            entry->first = new_block;
        }
        entry->last = new_block;
        pthread_mutex_unlock(&entry->list_mutex);

        atomic_fetch_add(&entry->total_size, to_copy);

        remaining -= to_copy;
        offset += to_copy;
    }

    pthread_cond_broadcast(&entry->updated);

    return 0;
}



void cache_entry_set_completed(cache_entry_t *entry) {
    if (!entry) return;
    pthread_mutex_lock(&entry->state_mutex);
    entry->completed = 1;
    pthread_mutex_unlock(&entry->state_mutex);
    pthread_cond_broadcast(&entry->updated);
}

void cache_entry_set_canceled(cache_entry_t *entry) {
    if (!entry) return;
    pthread_mutex_lock(&entry->state_mutex);
    entry->canceled = 1;
    pthread_mutex_unlock(&entry->state_mutex);
    pthread_cond_broadcast(&entry->updated);
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
