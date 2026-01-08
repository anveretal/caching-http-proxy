#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
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
#define DEFAULT_PORT            80

proxy_t *proxy;



void stop(int sig) {
    if (!proxy) return;
    proxy->running = 0;
    log_info("Stopped proxy");
}

void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s [OPTIONS]\n", program_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -p, --port PORT    Port to listen on (default: %d)\n", DEFAULT_PORT);
    fprintf(stderr, "  -h, --help         Show this help message\n");
}



int main(int argc, char **argv) {
    int err;
    int port = DEFAULT_PORT;
    
    static struct option long_options[] = {
        {"port", required_argument, 0, 'p'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "p:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                if (port <= 0 || port > 65535) {
                    fprintf(stderr, "Error: Invalid port number %s\n", optarg);
                    return 1;
                }
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

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

    proxy = proxy_create(cache, thread_pool, port);
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
