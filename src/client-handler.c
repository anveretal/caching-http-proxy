#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "client-handler.h"
#include "logger.h"

static pthread_mutex_t search_create_mutex;

static int streq(const char *s1, const char *s2, size_t len);
static int set_timeout(int sock, unsigned int ms);
static void disconnect(int sock);
static int connect_to_server(const char *host_name);

static phr_header_t *find_header(phr_header_t headers[], size_t num_headers, const char *name);
static size_t get_content_len(phr_header_t headers[], size_t num_headers);

static int send_data(int sock, const char *data, size_t len);
static int send_from_cache(int sock, cache_entry_t *cache);

static ssize_t read_and_parse_request(int sock, char *buf, size_t max_len, req_parse_t *parse_data);
static ssize_t handle_response(int sock_to_server, int sock_to_client, cache_entry_t *cache_entry, int *status);



void client_handler_init() {
    pthread_mutex_init(&search_create_mutex, NULL);
}

void client_handler_fini() {
    pthread_mutex_destroy(&search_create_mutex);
}



void handle_client(void *args) {
    int sock_to_client = ((client_handler_args_t*) args)->sock_to_client;
    cache_storage_t *cache_storage = ((client_handler_args_t*) args)->cache;
    free(args);

    int sock_to_server;
    char request[MAX_REQ_SIZE + 1] = {0};
    cache_entry_t *cache_entry = NULL;
    ssize_t req_len, resp_len;
    req_parse_t req_parse;
    int err;

    err = set_timeout(sock_to_client, TIMEOUT);
    if (err) {
        log_error("Failed to set timeout for client, error: %s", strerror(errno));
        disconnect(sock_to_client);
        return;
    }

    req_len = read_and_parse_request(sock_to_client, request, MAX_REQ_SIZE, &req_parse);
    if (req_len < 0) {
        log_error("Failed to read client request");
        disconnect(sock_to_client);
        return;
    }
    char path[req_parse.path_len + 1];
    memcpy(path, req_parse.path, req_parse.path_len);
    path[req_parse.path_len] = 0;

    if (!streq(req_parse.method, "GET", 3)) {
        log_error("Unsupported method");
        disconnect(sock_to_client);
        return;
    }

    pthread_mutex_lock(&search_create_mutex);   // Чтобы избежать дубликатов в кэше, 
                                                // в случае если оба клиента не нашли записи в кэше и добавили запись туда.

    /* Поиск записи в кэше и отправка */
    cache_entry = cache_storage_get(cache_storage, path);
    if (cache_entry) {
        pthread_mutex_unlock(&search_create_mutex);

        log_debug("Found cache entry for resource %s", path);

        err = send_from_cache(sock_to_client, cache_entry);
        cache_entry_dereference(cache_entry);
        disconnect(sock_to_client);

        if (err) {
            log_error("Failed to send response to client");
        }
        return;
    }

    /* Запись не найдена, обращаемся к серверу */
    log_debug("Cache entry for resource %s not found", path);

    cache_entry = cache_entry_create();
    if (!cache_entry) {
        pthread_mutex_unlock(&search_create_mutex);
        log_error("Failed to create cache entry");
        disconnect(sock_to_client);
        return;
    }

    err = cache_storage_put(cache_storage, path, cache_entry);
    pthread_mutex_unlock(&search_create_mutex);
    if (err) {
        log_error("Failed to add entry for resource %s", path);
        cache_entry_dereference(cache_entry);
        disconnect(sock_to_client);
        return;
    }

    /* Определяем доменное имя сервера */
    phr_header_t *host_header = find_header(req_parse.headers, req_parse.num_headers, "Host");
    if (!host_header) {
        log_error("Failed to fetch host name");
        cache_entry_set_canceled(cache_entry);
        cache_storage_remove(cache_storage, path);
        cache_entry_dereference(cache_entry);
        disconnect(sock_to_client);
        return;
    }
    char host_name[host_header->value_len + 1];
    memcpy(host_name, host_header->value, host_header->value_len);
    host_name[host_header->value_len] = 0;

    sock_to_server = connect_to_server(host_name);
    if (sock_to_server < 0) {
        log_error("Failed to connect to %s", host_name);
        cache_entry_set_canceled(cache_entry);
        cache_storage_remove(cache_storage, path);
        cache_entry_dereference(cache_entry);
        disconnect(sock_to_client);
        return;
    }
    log_info("Connected to server %s", host_name);

    err = send_data(sock_to_server, request, req_len);
    if (err) {
        log_error("Failed to send request to server, error: %s", strerror(errno));
        cache_entry_set_canceled(cache_entry);
        cache_storage_remove(cache_storage, path);
        cache_entry_dereference(cache_entry);
        disconnect(sock_to_client);
        disconnect(sock_to_server);
        return;
    }
    log_debug("Sent request of %ld bytes to server %s", req_len, host_name);

    int status;
    resp_len = handle_response(sock_to_server, sock_to_client, cache_entry, &status);
    disconnect(sock_to_client);
    disconnect(sock_to_server);

    if (resp_len < 0) {
        log_error("Error handling response");
        cache_entry_set_canceled(cache_entry);
        cache_storage_remove(cache_storage, path);
        cache_entry_dereference(cache_entry);
        return;
    }

    log_info("Server %s responded with %ld bytes, status: %d", host_name, resp_len, status);
    if (status != 200) {
        cache_entry_set_canceled(cache_entry);
        cache_storage_remove(cache_storage, path);
    }
    cache_entry_dereference(cache_entry);
}



static int streq(const char *s1, const char *s2, size_t len) {
    return strncmp(s1, s2, len) == 0;
}

static int set_timeout(int sock, unsigned int ms) {
    struct timeval timeout;
    timeout.tv_sec = ms / 1000;
    timeout.tv_usec = ms % 1000 * 1000;

    int err1 = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    int err2 = setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (err1 || err2) {
        return -1;
    }
    return 0;
}

static void disconnect(int sock) {
    shutdown(sock, SHUT_RDWR);
    close(sock);
}

static int connect_to_server(const char *host_name) {
    struct addrinfo *addr_info;
    int err;

    int sock_to_server = socket(AF_INET, SOCK_STREAM, 0);
    if (!sock_to_server) {
        log_error("connect_to_server: failed to create new socket");
        return -1;
    }

    err = set_timeout(sock_to_server, TIMEOUT);
    if (err) {
        log_error("connect_to_server: failed to set timeout, error: %s", strerror(errno));
        close(sock_to_server);
        return -1;
    }

    err = getaddrinfo(host_name, "http", NULL, &addr_info);
    if (err) {
        log_error("connect_to_server: failed to resolve server address");
        close(sock_to_server);
        return -1;
    }

    err = connect(sock_to_server, addr_info->ai_addr, addr_info->ai_addrlen);
    if (err) {
        log_error("connect_to_server: failed to connect, error: %s", strerror(errno));
        close(sock_to_server);
        freeaddrinfo(addr_info);
        return -1;
    }

    freeaddrinfo(addr_info);
    return sock_to_server;
}



static phr_header_t *find_header(phr_header_t headers[], size_t num_headers, const char *name) {
    size_t len = strlen(name);
    for (size_t i = 0; i < num_headers; i++) {
        if (headers[i].name_len == len && streq(headers[i].name, name, len)) {
            return &headers[i];
        }
    }
    return NULL;
}

static size_t get_content_len(phr_header_t headers[], size_t num_headers) {
    phr_header_t *cont_len_header = find_header(headers, num_headers, "Content-Length");
    if (!cont_len_header) return 0;

    char contentLength[cont_len_header->value_len + 1];
    memcpy(contentLength, cont_len_header->value, cont_len_header->value_len);
    contentLength[cont_len_header->value_len] = 0;

    long long contLen = atoll(contentLength);
    if (contLen < 0) return 0;
    return contLen;
}



static int send_data(int sock, const char *data, size_t len) {
    ssize_t sent_total = 0;
    ssize_t sent;

    while (sent_total != len) {
        sent = write(sock, data + sent_total, len - sent_total);
        if (sent == -1) return -1;
        sent_total += sent;
    }
    return 0;
}

static int send_from_cache(int sock, cache_entry_t *cache) {
    size_t sent_total = 0;
    size_t len_to_send;
    int err, ret;

    pthread_mutex_lock(&cache->mutex);

    while (1) {
        while (cache->size == sent_total && !cache->completed && !cache->canceled) {
            pthread_cond_wait(&cache->updated, &cache->mutex);
        }

        if (cache->canceled) {
            ret = -1;
            break;
        }

        len_to_send = cache->size - sent_total;
        err = send_data(sock, cache->buf + sent_total, len_to_send);
        if (err) {
            ret = -1;
            break;
        }
        sent_total = cache->size;

        if (cache->completed) {
            ret = 0;
            break;
        }
    }

    pthread_mutex_unlock(&cache->mutex);
    return ret;
}



static ssize_t read_and_parse_request(int sock, char *buf, size_t max_len, req_parse_t *parse_data) {
    int pret;
    ssize_t rret;
    size_t buflen = 0, prevbuflen = 0;

    while (1) {
        /* read the request */
        while ((rret = read(sock, buf + buflen, max_len - buflen)) == -1 && errno == EINTR);
        if (rret == -1) {
            log_error("Receive error: %s", strerror(errno));
            return -1;
        }
        if (rret == 0) {
            log_info("Peer socket shutdown");
            return -1;
        }

        prevbuflen = buflen;
        buflen += rret;

        /* parse the request */
        parse_data->num_headers = sizeof(parse_data->headers) / sizeof(parse_data->headers[0]);
        pret = phr_parse_request(
            buf, buflen, &parse_data->method, &parse_data->method_len, &parse_data->path, &parse_data->path_len,
            &parse_data->minor_version, parse_data->headers, &parse_data->num_headers, prevbuflen
        );

        if (pret > 0) {
            break;
        }

        else if (pret == -1) {
            log_error("Error parsing request");
            return -1;
        }

        /* request is incomplete, continue the loop */
        assert(pret == -2);
        if (buflen == max_len) {
            log_error("Request is too long");
            return -1;
        }
    }

    return buflen;
}

static ssize_t handle_response(int sock_to_server, int sock_to_client, cache_entry_t *cache_entry, int *status) {
    char buf[READ_BUF_LEN + 1];
    resp_parse_t parse;
    ssize_t recvd;
    size_t recvd_total = 0, header_len, content_len;
    char *header_end;
    int err;

    /* Ищем конец секции заголовков */
    do {
        if (recvd_total == READ_BUF_LEN) {
            log_error("Receive error: headers section is too long");
            return -1;
        }

        recvd = read(sock_to_server, buf + recvd_total, READ_BUF_LEN - recvd_total);
        if (recvd <= 0) {
            if (recvd == -1) log_error("Receive error: %s", strerror(errno));
            if (recvd == 0) log_error("Receive error: server disconnected");
            return -1;
        }

        recvd_total += recvd;
        buf[recvd_total] = 0;
    } while ((header_end = strstr(buf, "\r\n\r\n")) == NULL); // пока не нашли подстроку в строке
    header_end += strlen("\r\n\r\n");
    header_len = header_end - buf;

    /* Парсим секцию заголовков */
    parse.num_headers = sizeof(parse.headers) / sizeof(parse.headers[0]);
    err = phr_parse_response(
        buf, header_len, &parse.minor_version, &parse.status, &parse.msg,
        &parse.msg_len, parse.headers, &parse.num_headers, 0
    );
    if (err < 0) {
        log_error("Failed to parse response, error: %i", err);
        return -1;
    }
    *status = parse.status;

    content_len = get_content_len(parse.headers, parse.num_headers);

    /* Отправляем клиенту все данные, полученные на текущий момент */
    err = send_data(sock_to_client, buf, recvd_total);
    if (err) {
        log_error("Failed to send data back to client");
        return -1;
    }

    /* Если ответ неуспешный, его не надо сохранять */
    if (parse.status != 200) {
        cache_entry = NULL;
    }

    /* Добавляем в запись все данные, полученные на текущий момент */
    err = cache_entry_append(cache_entry, buf, recvd_total);
    if (err) {
        log_error("Failed to append data to cache entry");
        return -1;
    }

    /* Получаем оставшиеся данные от сервера, пересылаем клиенту и сохраняем в кэш */
    ssize_t remaining = header_len + content_len - recvd_total;
    while (remaining > 0) {
        recvd = read(sock_to_server, buf, READ_BUF_LEN);
        if (recvd <= 0) {
            if (recvd == -1) log_error("Receive error: %s", strerror(errno));
            if (recvd == 0) log_error("Receive error: server disconnected");
            return -1;
        }

        remaining -= recvd;
        recvd_total += recvd;

        err = send_data(sock_to_client, buf, recvd);
        if (err) {
            log_error("Failed to send data back to client");
            return -1;
        }

        err = cache_entry_append(cache_entry, buf, recvd);
        if (err) {
            log_error("Failed to append data to cache entry");
            return -1;
        }
    }

    cache_entry_set_completed(cache_entry);
    return recvd_total;
}
