#ifndef S5TUNNEL_H
#define S5TUNNEL_H
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/socket.h>

typedef struct s5_remote {
    int protocol;
    const char* local_host;
    const char* local_port;
    uint8_t remote_type;
    size_t remote_len;
    uint8_t* remote;
    struct s5_remote *next;
} s5_remote_t;

typedef struct s5_config {
    const char* server_host;
    const char* server_port;

    bool auth_enabled;
    const char* user;
    const char* passwd;

    s5_remote_t *remotes;
} s5_config_t;

typedef struct s5_context {
    const s5_config_t *config;
    const s5_remote_t *remote;
} s5_context_t;

typedef struct s5_thread {
    pthread_t thread;
    s5_context_t ctx;
    struct s5_thread *next;
} s5_thread_t;

typedef struct s5_fdpair {
    int local;
    int remote;
} s5_fdpair_t;

enum s5_states {
    IDLE, METHOD_SENT, AUTH_SENT, REQUEST_SENT
};

void s5_run(const s5_config_t *config);
ssize_t mks5addr(uint8_t atyp, const char *host, in_port_t port, uint8_t **rslt);

#endif 