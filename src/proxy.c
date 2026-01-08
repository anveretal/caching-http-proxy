#define _GNU_SOURCE

#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "client-handler.h"
#include "logger.h"
#include "proxy.h"

#define BACKLOG         30



static int create_server_socket(int port);

static int create_gc_timer(proxy_t *proxy);
static void fire_gc_timer(proxy_t *proxy);



proxy_t *proxy_create(cache_storage_t *cache, thread_pool_t *threadpool, int port) {
    if (!cache) {
        log_error("proxy_create: invalid cache");
        return NULL;
    }

    proxy_t *proxy = malloc(sizeof(*proxy));
    if (!proxy) {
        log_error("proxy_create: allocation failed");
        return NULL;
    }

    proxy->port = port;
    proxy->server_socket = create_server_socket(port);
    if (proxy->server_socket == -1) {
        free(proxy);
        return NULL;
    }

    proxy->running = 1;
    proxy->cache = cache;
    proxy->threadpool = threadpool;

    proxy->gc_finished = 0;
    pthread_cond_init(&proxy->gc_finished_cond, NULL);
    pthread_mutex_init(&proxy->mutex, NULL);

    int err = create_gc_timer(proxy);
    if (err) {
        close(proxy->server_socket);
        pthread_cond_destroy(&proxy->gc_finished_cond);
        pthread_mutex_destroy(&proxy->mutex);
        free(proxy);
        return NULL;
    }

    client_handler_init();

    return proxy;
}

void proxy_destroy(proxy_t *proxy) {
    if (!proxy) return;

    pthread_mutex_lock(&proxy->mutex);

    proxy->running = 0;
    close(proxy->server_socket);

    fire_gc_timer(proxy);
    while (!proxy->gc_finished) {
        pthread_cond_wait(&proxy->gc_finished_cond, &proxy->mutex);
    }

    timer_delete(proxy->gc_timer);

    pthread_mutex_unlock(&proxy->mutex);
    pthread_mutex_destroy(&proxy->mutex);
    pthread_cond_destroy(&proxy->gc_finished_cond);
    free(proxy);

    client_handler_fini();
}



int proxy_start(proxy_t *proxy) {
    int err = listen(proxy->server_socket, BACKLOG);
    if (err) return -1;

    log_info("Proxy started on port %d", proxy->port);

    while (proxy->running) {
        int client_socket = accept(proxy->server_socket, NULL, NULL);
        if (client_socket < 0) {
            log_error("Error accepting connection: %s", strerror(errno));
            continue;
        }

        log_info("Accepted new connection");

        client_handler_args_t *args = malloc(sizeof(*args));
        if (!args) {
            log_error("Failed to allocate memory for client handler arguments");
            shutdown(client_socket, SHUT_RDWR);  // запретить чтение и запись
            close(client_socket);
            continue;
        }

        args->sock_to_client = client_socket;
        args->cache = proxy->cache;
        thread_pool_submit(proxy->threadpool, handle_client, args);
    }

    return 0;
}



void garbage_collector_routine(union sigval arg) {
    proxy_t *proxy = (proxy_t*) arg.sival_ptr;

    pthread_mutex_lock(&proxy->mutex);

    if (!proxy->running) {
        proxy->gc_finished = 1;
        pthread_cond_signal(&proxy->gc_finished_cond);
        pthread_mutex_unlock(&proxy->mutex);
        log_debug("Garbage collector finished");
        return;
    }

    int removed_entries = cache_storage_clean(proxy->cache);
    pthread_mutex_unlock(&proxy->mutex);

    log_info("Garbage collector: removed %i cache entries", removed_entries);
}



static int create_server_socket(int port) {
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        log_error("Failed to create server socket, error: %s", strerror(errno));
        return -1;
    }

    int true = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(true));

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(port);

    int err = bind(server_socket, (struct sockaddr*) &saddr, sizeof(saddr));
    if (err) {
        log_error("Failed to bind server socket, error: %s", strerror(errno));
        close(server_socket);
        return -1;
    }

    return server_socket;
}

static int create_gc_timer(proxy_t *proxy) {
    struct sigevent event;
    event.sigev_notify = SIGEV_THREAD;
    event.sigev_signo = 0;
    event.sigev_value.sival_ptr = proxy;
    event.sigev_notify_function = garbage_collector_routine;
    event.sigev_notify_attributes = NULL;

    struct itimerspec tmr_spec;
    tmr_spec.it_value.tv_sec = EXPIRY_TIME;
    tmr_spec.it_value.tv_nsec = 0;
    tmr_spec.it_interval.tv_sec = EXPIRY_TIME;
    tmr_spec.it_interval.tv_nsec = 0;

    int err = timer_create(CLOCK_REALTIME, &event, &proxy->gc_timer);
    if (err) {
        log_error("Failed to create timer for garbage collector");
        return -1;
    }

    err = timer_settime(proxy->gc_timer, 0, &tmr_spec, NULL);
    if (err) {
        log_error("Failed to arm timer for garbage collector");
        return -1;
    }

    return 0;
}

static void fire_gc_timer(proxy_t *proxy) {
    struct itimerspec tmr_spec;
    tmr_spec.it_value.tv_sec = 0;
    tmr_spec.it_value.tv_nsec = 1000;
    tmr_spec.it_interval.tv_sec = 0;
    tmr_spec.it_interval.tv_nsec = 0;

    timer_settime(proxy->gc_timer, 0, &tmr_spec, NULL);
}
