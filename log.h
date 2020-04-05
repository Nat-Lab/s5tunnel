#include <stdio.h>
#define log_debug(fmt, ...) __log("DEBUG", fmt, ## __VA_ARGS__)
#define log_info(fmt, ...) __log("INFO ", fmt, ## __VA_ARGS__)
#define log_warn(fmt, ...) __log("WARN ", fmt, ## __VA_ARGS__)
#define log_error(fmt, ...) __log("ERROR", fmt, ## __VA_ARGS__)
#define log_fatal(fmt, ...) __log("FATAL", fmt, ## __VA_ARGS__)
#define __log(log_level, fmt, ...) fprintf(stderr, "[" log_level "] %s:%d %s: " fmt, __FILE__, __LINE__, __FUNCTION__, ## __VA_ARGS__)