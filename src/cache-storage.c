#include <stdlib.h>
#include <string.h>

#include "cache-storage.h"
#include "logger.h"

static unsigned int hash(const char *str, size_t len) {
    unsigned int hash = 0;
    for (size_t i = 0; i < len; i++) {
        hash = hash * 31 + *str++;
    }
    return hash % MAP_SIZE;
}

static int streq(char *s1, char *s2) {
    return strcmp(s1, s2) == 0;
}



cache_storage_t *cache_storage_create() {
    cache_storage_t *storage = malloc(sizeof(*storage));
    if (!storage) return NULL;

    storage->map = calloc(MAP_SIZE, sizeof(node_t*));
    if (!storage->map) {
        free(storage);
        return NULL;
    }

    pthread_mutex_init(&storage->mutex, NULL);

    log_debug("cache_storage_create: created %p", storage);

    return storage;
}

void cache_storage_destroy(cache_storage_t *storage) {
    if (!storage) return;

    pthread_mutex_lock(&storage->mutex);

    for (int i = 0; i < MAP_SIZE; i++) {
        node_t* current = storage->map[i];
        while (current) {
            node_t* temp = current;
            current = current->next;

            /* удаляем ссылку и очищаем ресурсы ноды */
            cache_entry_dereference(temp->response);
            free(temp->request);
            free(temp);
        }
    }

    free(storage->map);
    pthread_mutex_unlock(&storage->mutex);
    pthread_mutex_destroy(&storage->mutex);

    log_debug("cache_storage_destroy: destroyed %p", storage);
    free(storage);
}



int cache_storage_put(cache_storage_t *storage, char *req, cache_entry_t *resp) {
    if (!storage || !req || !resp) return 0;

    pthread_mutex_lock(&storage->mutex);

    size_t req_len = strlen(req);
    unsigned long index = hash(req, req_len);
    node_t *current = storage->map[index];

    /* Проверяем на наличие записи по данному запросу */
    while (current) {
        if (streq(current->request, req)) {                     // запись найдена
            if (current->response != resp) {
                cache_entry_dereference(current->response);     // удаляем ссылку на старый ответ
                current->response = resp;                       // заменяем на новый ответ
                cache_entry_reference(resp);                    // добавлена ссылка на новый ответ
                log_debug("cache_storage_put: modified node, key '%s'", req);
            }

            pthread_mutex_unlock(&storage->mutex);
            return 0;
        }
        current = current->next;
    }

    /* Запись не найдена, создаем новую */
    node_t *new_node = malloc(sizeof(*new_node));
    char *request = malloc((req_len + 1) * sizeof(*request));
    if (!new_node || !request) {
        free(new_node);
        free(request);
        pthread_mutex_unlock(&storage->mutex);
        return -1;
    }

    memcpy(request, req, req_len);              // сохраняем содержимое запроса
    request[req_len] = 0;
    new_node->request = request;

    new_node->response = resp;
    cache_entry_reference(resp);                // добавлена ссылка на новый ответ

    new_node->next = storage->map[index];       // добавлем в начало списка
    storage->map[index] = new_node;

    log_debug("cache_storage_put: created new node, key '%s'", req);
    pthread_mutex_unlock(&storage->mutex);
    return 0;
}

cache_entry_t *cache_storage_get(cache_storage_t *storage, char *req) {
    if (!storage || !req) return NULL;

    pthread_mutex_lock(&storage->mutex);

    size_t req_len = strlen(req);
    unsigned long index = hash(req, req_len);
    node_t *current = storage->map[index];

    while (current) {
        if (streq(current->request, req)) {                 // запись найдена
            cache_entry_reference(current->response);       // добавили ссылку на эту запись
            log_debug("cache_storage_get: found node, key '%s'", current->request);
            pthread_mutex_unlock(&storage->mutex);
            return current->response;
        }
        current = current->next;
    }

    pthread_mutex_unlock(&storage->mutex);
    return NULL;
}



int cache_storage_remove(cache_storage_t *storage, char *req) {
    if (!storage || !req) return 0;

    pthread_mutex_lock(&storage->mutex);

    size_t req_len = strlen(req);
    unsigned long index = hash(req, req_len);
    node_t* current = storage->map[index];
    node_t* previous = NULL;

    while (current) {
        if (streq(current->request, req)) {                     // запись найдена
            if (previous) {
                previous->next = current->next;
            } else {
                storage->map[index] = current->next;
            }

            log_debug("cache_storage_remove: found node, key '%s'", current->request);

            cache_entry_dereference(current->response);         // ссылки из мапы больше нет, удаляем
            free(current->request);                             // очищаем память, занятую нодой, но не ответом
            free(current);
            pthread_mutex_unlock(&storage->mutex);
            return 0;
        }
        previous = current;
        current = current->next;
    }

    pthread_mutex_unlock(&storage->mutex);
    return -1;
}
