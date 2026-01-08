#ifndef CACHE_PROXY_LOGGER
#define CACHE_PROXY_LOGGER

enum {
    LOG_CRITICAL    = 0,
    LOG_ERROR       = 1,
    LOG_INFO        = 2,
    LOG_DEBUG       = 3
} typedef log_level_t;

struct {
    log_level_t log_level;
} typedef logger_t;

int logger_init(log_level_t logLevel);
void logger_fini();

void log_critical(char *format, ...);
void log_error(char *format, ...);
void log_info(char *format, ...);
void log_debug(char *format, ...);

#endif /* CACHE_PROXY_LOGGER */
