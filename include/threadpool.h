#ifndef CACHE_PROXY_THREAD_POOL
#define CACHE_PROXY_THREAD_POOL

#include <stdatomic.h>
#include <pthread.h>

typedef struct {
    long id;
    void (*run)(void *);
    void *arg;
} task_t;

typedef struct {
    task_t *tasks;
    size_t capacity;
    size_t size;
    int first;
    int last;

    pthread_mutex_t mutex;
    pthread_cond_t got_tasks;
    pthread_cond_t got_slots;

    pthread_t *threads;
    int num_threads;

    atomic_int stopped;
} thread_pool_t;

thread_pool_t *thread_pool_create(int num_threads, size_t queue_capacity);
void thread_pool_submit(thread_pool_t *pool, void (*run) (void *), void *arg);
void thread_pool_stop(thread_pool_t *pool);

#endif // CACHE_PROXY_THREAD_POOL
