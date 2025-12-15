#define _GNU_SOURCE

#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "client-handler.h"
#include "logger.h"
#include "proxy.h"

#define PORT            80
#define BACKLOG         30



static int create_server_socket() {
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
    saddr.sin_port = htons(PORT);

    int err = bind(server_socket, (struct sockaddr*) &saddr, sizeof(saddr));
    if (err) {
        log_error("Failed to bind server socket, error: %s", strerror(errno));
        close(server_socket);
        return -1;
    }

    return server_socket;
}



proxy_t *proxy_create(cache_storage_t *cache, thread_pool_t *threadpool) {
    if (!cache) {
        log_error("proxy_create: invalid cache");
        return NULL;
    }

    proxy_t *proxy = malloc(sizeof(*proxy));
    if (!proxy) {
        log_error("proxy_create: allocation failed");
        return NULL;
    }

    proxy->server_socket = create_server_socket();
    if (proxy->server_socket == -1) {
        free(proxy);
        return NULL;
    }

    proxy->running = 1;
    proxy->cache = cache;
    proxy->threadpool = threadpool;

    client_handler_init();

    return proxy;
}

void proxy_destroy(proxy_t *proxy) {
    if (!proxy) return;

    proxy->running = 0;
    close(proxy->server_socket);

    free(proxy);

    client_handler_fini();
}

int proxy_start(proxy_t *proxy) {
    int err = listen(proxy->server_socket, BACKLOG);
    if (err) return -1;

    log_info("Proxy started");

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
