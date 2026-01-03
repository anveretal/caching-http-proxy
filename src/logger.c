#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "logger.h"

#define LOG_GENERAL(log_level, format)                  \
    va_list args;                                       \
    va_start(args, format);                             \
    logger_log(log_level, format, args);                \
    va_end(args)

static logger_t *logger;



static void logger_log(char *log_level, char *format, va_list args) {
    fprintf(stderr, "[%s]: ", log_level);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
}



int logger_init(log_level_t log_level) {
    logger = malloc(sizeof(*logger));
    if (!logger) {
        return -1;
    }
    logger->log_level = log_level;
    return 0;
}

void logger_fini() {
    free(logger);
}



void log_critical(char *format, ...) {
    if (logger->log_level < LOG_CRITICAL) return;
    LOG_GENERAL("CRITICAL", format);
}

void log_error(char *format, ...) {
    if (logger->log_level < LOG_ERROR) return;
    LOG_GENERAL("ERROR", format);
}

void log_info(char *format, ...) {
    if (logger->log_level < LOG_INFO) return;
    LOG_GENERAL("INFO", format);
}

void log_debug(char *format, ...) {
    if (logger->log_level < LOG_DEBUG) return;
    LOG_GENERAL("DEBUG", format);
}
