#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cache-storage.h"
#include "logger.h"
#include "proxy.h"
#include "threadpool.h"

#define NUM_WORKERS             16
#define TASK_QUEUE_CAP          100

proxy_t *proxy;

void stop(int sig) {
    if (!proxy) return;
    proxy->running = 0;
    log_info("Stopped proxy");
}

int main(int argc, char **argv) {
    int err;
    logger_init(LOG_DEBUG);

    struct sigaction act;
    act.sa_handler = stop;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;

    err = sigaction(SIGINT, &act, NULL);
    if (err) {
        log_critical("Failed to setup SIGINT handler, error: %s", strerror(errno));
        abort();
    }

    act.sa_handler = SIG_IGN;               // Обработчик, игнорирующий сигнал.
    err = sigaction(SIGPIPE, &act, NULL);   // SIGPIPE (при попыткe писать в закрытый сокет).
    if (err) {
        log_critical("Failed to setup SIGPIPE handler, error: %s", strerror(errno));
        abort();
    }

    cache_storage_t *cache = cache_storage_create();
    if (!cache) {
        log_critical("Failed to create cache storage");
        abort();
    }

    thread_pool_t *thread_pool = thread_pool_create(NUM_WORKERS, TASK_QUEUE_CAP);
    if (!thread_pool) {
        log_critical("Failed to create thread_pool");
        abort();
    }

    proxy = proxy_create(cache, thread_pool);
    if (!proxy) {
        log_critical("Error creating proxy");
        abort();
    }

    err = proxy_start(proxy);
    if (err) {
        log_critical("Error starting proxy");
        abort();
    }

    proxy_destroy(proxy);
    thread_pool_stop(thread_pool);
    cache_storage_destroy(cache);

    logger_fini();

    return 0;
}
