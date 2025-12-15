#include <stdlib.h>

#include "logger.h"
#include "threadpool.h"

static long id_cnt;

static void *worker_routine(void *arg);

thread_pool_t *thread_pool_create(int num_threads, size_t queue_capacity) {
    thread_pool_t *pool = malloc(sizeof(*pool));
    if (pool == NULL) return NULL;

    pool->tasks = calloc(queue_capacity, sizeof(task_t));
    if (pool->tasks == NULL) {
        free(pool);
        return NULL;
    }

    pool->threads = calloc(num_threads, sizeof(pthread_t));
    if (pool->threads == NULL) {
        free(pool->tasks);
        free(pool);
        return NULL;
    }

    pool->capacity = queue_capacity;
    pool->size = 0;
    pool->first = 0;
    pool->last = 0;
    pool->num_threads = num_threads;
    pool->stopped = 0;

    pthread_mutex_init(&pool->mutex, NULL);
    pthread_cond_init(&pool->got_tasks, NULL);
    pthread_cond_init(&pool->got_slots, NULL);

    for (int i = 0; i < num_threads; i++) {
        pthread_create(&pool->threads[i], NULL, worker_routine, pool);
    }

    return pool;
}

void thread_pool_submit(thread_pool_t *pool, void (*run) (void *), void *arg) {
    if (pool->stopped) {
        log_error("Can't submit a new task: thread pool is stopped");
        return;
    }

    pthread_mutex_lock(&pool->mutex);

    while (pool->size == pool->capacity && !pool->stopped) {
        pthread_cond_wait(&pool->got_slots, &pool->mutex);
    }

    if (pool->stopped) {
        pthread_mutex_unlock(&pool->mutex);
        return;
    }

    pool->tasks[pool->last].id = id_cnt++;
    pool->tasks[pool->last].run = run;
    pool->tasks[pool->last].arg = arg;
    pool->last = (pool->last + 1) % pool->capacity;
    pool->size++;

    pthread_cond_signal(&pool->got_tasks);
    pthread_mutex_unlock(&pool->mutex);
}

void thread_pool_stop(thread_pool_t *pool) {
    pool->stopped = 1;

    pthread_cond_broadcast(&pool->got_tasks);
    pthread_cond_broadcast(&pool->got_slots);

    for (int i = 0; i < pool->num_threads; i++) {
        pthread_join(pool->threads[i], NULL);
    }

    free(pool->tasks);
    free(pool->threads);

    pthread_mutex_destroy(&pool->mutex);
    pthread_cond_destroy(&pool->got_tasks);
    pthread_cond_destroy(&pool->got_slots);

    free(pool);
}



static void *worker_routine(void *arg) {
    thread_pool_t *pool = (thread_pool_t*) arg;
    while (1) {
        pthread_mutex_lock(&pool->mutex);

        while (pool->size == 0 && !pool->stopped) {
            pthread_cond_wait(&pool->got_tasks, &pool->mutex);
        }

        if (pool->stopped) {
            pthread_mutex_unlock(&pool->mutex);
            pthread_exit(NULL);
        }

        task_t task = pool->tasks[pool->first];
        pool->first = (pool->first + 1) % pool->capacity;
        pool->size--;

        pthread_cond_signal(&pool->got_slots);
        pthread_mutex_unlock(&pool->mutex);

        task.run(task.arg);
    }
}
