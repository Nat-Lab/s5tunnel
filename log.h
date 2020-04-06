#ifndef S5TUNNEL_LOG
#define S5TUNNEL_LOG
#include <stdio.h>
#define __log(log_level, fmt, ...) fprintf(stderr, "[" log_level "] %s:%d %s: " fmt, __FILE__, __LINE__, __FUNCTION__, ## __VA_ARGS__)
#define log_info(fmt, ...) __log("INFO ", fmt, ## __VA_ARGS__)
#define log_warn(fmt, ...) __log("WARN ", fmt, ## __VA_ARGS__)
#define log_error(fmt, ...) __log("ERROR", fmt, ## __VA_ARGS__)
#define log_fatal(fmt, ...) __log("FATAL", fmt, ## __VA_ARGS__)

#ifdef S5TUNNEL_DEBUG
#define log_debug(fmt, ...) __log("DEBUG", fmt, ## __VA_ARGS__)
#else
#define log_debug(fmt, ...)
#endif 

#endif S5TUNNEL_LOG