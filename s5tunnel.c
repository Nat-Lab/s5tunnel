#include "s5tunnel.h"
#include "socks5.h"
#include "log.h"
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>

void sockaddr_to_str(const struct sockaddr *sa, char *s, size_t len) {
    if (sa->sa_family == AF_INET) inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr), s, len);
    else if (sa->sa_family == AF_INET6) inet_ntop(AF_INET6, &(((struct sockaddr_in *)sa)->sin_addr), s, len);
    else strncpy(s, "(unknow)", len);
}

int gai_connect(const char *host, const char *port, int socktype, int protocol) {
    log_debug("connecting to %s:%s...\n", host, port);

    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = PF_UNSPEC;
    hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG;
    hints.ai_socktype = socktype;
    hints.ai_protocol = protocol;
    char remote_address_str[INET6_ADDRSTRLEN];

    int s = 0;
    if ((s = getaddrinfo(host, port, &hints, &result)) != 0) {
        log_fatal("getaddrinfo(): %s\n", gai_strerror(s));
        return -1;
    }

    for (const struct addrinfo *cur = result; cur != NULL; cur = cur->ai_next) {
        sockaddr_to_str(cur->ai_addr, remote_address_str, INET6_ADDRSTRLEN);
        log_debug("trying %s...\n", remote_address_str);

        int fd = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
        if (fd < 0) {
            log_error("socket(): %s\n", strerror(errno));
            continue;
        }

        if (connect(fd, cur->ai_addr, cur->ai_addrlen) < 0) {
            log_error("connect(): %s\n", strerror(errno));
            close(fd);
            continue;
        }

        log_debug("connected to %s.\n", remote_address_str);
        freeaddrinfo(result);
        return fd;
    }

    freeaddrinfo(result);
    log_fatal("failed to connect to %s:%s.\n", host, port);
    return -1;
}

int gai_bind(const char *host, const char *port, int socktype, int protocol) {
    log_debug("binding on %s:%s...\n", host, port);

    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = PF_UNSPEC;
    hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | AI_PASSIVE;
    hints.ai_socktype = socktype;
    hints.ai_protocol = protocol;
    char remote_address_str[INET6_ADDRSTRLEN];

    int s = 0;
    if ((s = getaddrinfo(host, port, &hints, &result)) != 0) {
        log_fatal("getaddrinfo(): %s\n", gai_strerror(s));
        return -1;
    }

    for (const struct addrinfo *cur = result; cur != NULL; cur = cur->ai_next) {
        sockaddr_to_str(cur->ai_addr, remote_address_str, INET6_ADDRSTRLEN);
        log_debug("trying %s...\n", remote_address_str);

        int fd = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
        if (fd < 0) {
            log_error("socket(): %s\n", strerror(errno));
            continue;
        }

        if (bind(fd, cur->ai_addr, cur->ai_addrlen) < 0) {
            log_error("bind(): %s\n", strerror(errno));
            close(fd);
            continue;
        }

        log_debug("binded on %s.\n", remote_address_str);
        freeaddrinfo(result);
        return fd;
    }

    freeaddrinfo(result);
    log_fatal("failed to bind on %s:%s.\n", host, port);
    return -1;
}

int s5_new_connection(const s5_config_t *config, const s5_remote_t *remote) {
    int fd = gai_connect(config->server_host, config->server_port, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        log_error("can't connect to socks5 server.\n");
        return -1;
    }

    s5_method_request_t mreq;
    mreq.ver = SOCK_VER;
    mreq.nmethods = 1;
    mreq.methods = config->auth_enabled ? S5_AUTH_USER_PASSWD : S5_AUTH_NONE;
    ssize_t sz = write(fd, &mreq, sizeof(s5_method_request_t));
    if (sz < 0) {
        log_fatal("write(): %s\n", strerror(errno));
        goto err_new_conn;
    }

    int state = METHOD_SENT;
    uint8_t buffer[1024];
    uint8_t send_buffer[1024];

    while (1) {
        ssize_t len = read(fd, buffer, sizeof(buffer));
        if (len < 0) {
            log_fatal("read(): %s\n", strerror(errno));
            goto err_new_conn;
        }

        if (state == METHOD_SENT) {
            if (len != sizeof(s5_method_reply_t)) {
                log_fatal("bad s5_method_reply message.\n");
                goto err_new_conn;
            }

            s5_method_reply_t *reply = (s5_method_reply_t *) buffer;

            if (reply->ver != SOCK_VER) {
                log_fatal("bad remote server version: %d.\n", reply->ver);
                goto err_new_conn;
            }

            if (reply->method == S5_AUTH_BAD) {
                log_fatal("remote: bad auth.\n");
                goto err_new_conn;
            }

            if (reply->method != S5_AUTH_NONE && reply->method != S5_AUTH_USER_PASSWD) {
                log_fatal("unknow server auth method: %d.\n", reply->method);
                goto err_new_conn;
            }

            if (reply->method == S5_AUTH_NONE) {
                if (config->auth_enabled) {
                    log_fatal("remote server does not support auth.\n");
                    goto err_new_conn;
                }
                state = AUTH_SENT;
            }

            if (reply->method == S5_AUTH_USER_PASSWD) {
                if (!config->auth_enabled) {
                    log_fatal("remote server need auth.\n");
                    goto err_new_conn;
                }
                size_t ulen = strnlen(config->user, 255);
                size_t plen = strnlen(config->passwd, 255);
                size_t pkt_len = ulen + plen + 3;
                send_buffer[0] = 1;
                send_buffer[1] = ulen;
                memcpy(send_buffer + 2, config->user, ulen);
                send_buffer[ulen + 2] = plen;
                memcpy(send_buffer + ulen + 3, config->passwd, plen);
                write(fd, send_buffer, pkt_len);
                state = AUTH_SENT;
            }
        }

        if (state == AUTH_SENT) {
            if (config->auth_enabled) {
                if (len != 2) {
                    log_fatal("bad auth reply message from server: invalid len (%zu).\n", len);
                    goto err_new_conn;
                }

                if (buffer[0] != 1) {
                    log_fatal("bad auth reply message from server: bad version (%d).\n", buffer[0]);
                    goto err_new_conn;
                }

                if (buffer[1] != 0) {
                    log_fatal("auth failed.\n");
                    goto err_new_conn;
                }
            }

            s5_request_hdr_t *request = (s5_request_hdr_t *) send_buffer;
            request->ver = 5;
            request->cmd = remote->protocol == IPPROTO_UDP ? CMD_UDP_ASSOC : CMD_CONNECT;
            request->rsv = 0;
            request->atyp = remote->remote_type;

            uint8_t *buf_ptr = send_buffer + sizeof(s5_request_hdr_t);
            size_t pkt_len = remote->remote_len + sizeof(s5_request_hdr_t);

            if (pkt_len > sizeof(send_buffer)) {
                log_fatal("internal error: send buffer overflow.\n");
                goto err_new_conn;
            }

            memcpy(buf_ptr, remote->remote, remote->remote_len);
            write(fd, send_buffer, pkt_len);
            state = REQUEST_SENT;
            continue;
        }

        if (state == REQUEST_SENT) {
            s5_reply_hdr_t *reply = (s5_reply_hdr_t *) buffer;

            if (reply->ver != SOCK_VER) {
                log_fatal("bad remote server version: %d.\n", reply->ver);
                goto err_new_conn;
            }

            if (reply->rep != REP_OK) {
                log_fatal("remote request rejected: %d.\n", reply->rep);
                goto err_new_conn;
            }
            
            if (remote->protocol == IPPROTO_UDP) {
                /** todo **/
            }

            return fd;
        }
    }

err_new_conn:
    close(fd);
    return -1;
}

void fdbridge(int a, int b) {
    struct pollfd fds[2];
    fds[0].fd = a;
    fds[1].fd = b;
    fds[0].events = fds[1].events = POLLIN;
    uint8_t buffer[65536];
    bool ain = false, bin = false;

    while (1) {
        if (poll(fds, 2, -1) < 0) {
            log_fatal("poll(): %s\n", strerror(errno));
            goto br_err;
        }

        if (fds[0].revents & POLLIN) {
            ain = true;
            ssize_t rsz = read(fds[0].fd, buffer, sizeof(buffer));
            if (rsz < 0) {
                log_error("read(): %s\n", strerror(errno));
                goto br_err;
            }
            if (rsz == 0) {
                log_debug("read(): fd closed.\n");
                goto br_done;
            }
            ssize_t wsz = write(fds[1].fd, buffer, (size_t) rsz);
            if (wsz < 0) {
                log_error("write(): %s\n", strerror(errno));
                goto br_err;
            }
            if (wsz != rsz) {
                log_warn("inconsistent write size.\n");
            }
        }

        if (fds[1].revents & POLLIN) {
            bin = true;
            ssize_t rsz = read(fds[1].fd, buffer, sizeof(buffer));
            if (rsz < 0) {
                log_error("read(): %s\n", strerror(errno));
                return;
            }
            if (rsz == 0) return;
            ssize_t wsz = write(fds[0].fd, buffer, (size_t) rsz);
            if (wsz < 0) {
                log_error("write(): %s\n", strerror(errno));
                goto br_err;
            }
            if (wsz != rsz) {
                log_warn("inconsistent write size.\n");
            }
        }

        if (!ain && !bin) {
            log_warn("poll() returned but nothing ready.\n");
        }

        ain = bin = false;
    }

br_err:
    log_error("broken pipe.\n");

br_done:
    return;
}

void* s5_worker_tcp_conn(void *p) {
    s5_fdpair_t *fds = (s5_fdpair_t *) p;
    fdbridge(fds->local, fds->remote);
    close(fds->remote);
    close(fds->local);
    log_debug("connection closed.\n");
    free(p);

    return NULL;
}

void* s5_worker_tcp(void *ctx) {
    s5_context_t *context = (s5_context_t *) ctx;
    int fd = gai_bind(context->remote->local_host, context->remote->local_port, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) return NULL;

    if (listen(fd, 5) < 0) {
        log_fatal("listen(): %s\n", strerror(errno));
        return NULL;
    }

    s5_thread_t *threads, *cur;
    threads = (s5_thread_t *) malloc(sizeof(s5_thread_t));
    cur = threads;

    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(struct sockaddr_storage);
    char client_addr_str[INET6_ADDRSTRLEN];

    while (1) {
        int lfd = accept(fd, (struct sockaddr *) &client_addr, &client_addr_len);
        if (lfd < 0) {
            log_fatal("accept(): %s\n", strerror(errno));
            goto err_tcp;
        }
        sockaddr_to_str((struct sockaddr *) &client_addr, client_addr_str, INET6_ADDRSTRLEN);
        log_debug("new tcp client: %s -> %s:%s\n", client_addr_str, context->remote->local_host, context->remote->local_port);
        int rfd = s5_new_connection(context->config, context->remote);
        if (rfd < 0) {
            log_error("can't create new socks5 connection.\n");
            close(lfd);
            continue;
        }
        s5_fdpair_t *p = (s5_fdpair_t *) malloc(sizeof(s5_fdpair_t));
        p->local = lfd;
        p->remote = rfd;

        int s = pthread_create(&(cur->thread), NULL, s5_worker_tcp_conn, p);
        if (s != 0) {
            close(lfd);
            close(rfd);
            log_fatal("failed to start connection worker: %s\n", strerror(s));
            continue;
        }

        cur->next = (s5_thread_t *) malloc(sizeof(s5_thread_t));
        cur = cur->next;
    }

err_tcp:
    close(fd);
    return NULL;
}

void* s5_worker_udp(void *ctx) {
    s5_context_t *context = (s5_context_t *) ctx;
    // todo

err_udp:
    return NULL;
}

void s5_run(const s5_config_t *config) {
    if (config->remotes == NULL) {
        log_error("no tunnel configured.\n");
        return;
    }

    s5_thread_t *threads, *cur;
    threads = (s5_thread_t *) malloc(sizeof(s5_thread_t));
    cur = threads;
    for (const s5_remote_t *r = config->remotes; r != NULL; r = r->next) {
        cur->ctx.config = config;
        cur->ctx.remote = r;

        int s = pthread_create(&(cur->thread), NULL, r->protocol == IPPROTO_UDP ? s5_worker_udp : s5_worker_tcp, &(cur->ctx));
        if (s != 0) {
            log_fatal("failed to start worker: %s\n", strerror(s));
            goto err_run;
        }
        cur->next = (s5_thread_t *) malloc(sizeof(s5_thread_t));
        cur = cur->next;
        cur->thread = 0;
        cur->next = NULL;
    }

    for (cur = threads; cur != NULL; cur = cur->next) {
        if (cur->thread != 0) {
            pthread_join(cur->thread, NULL);
            log_warn("worker exited.\n");
        } 
    }

    log_warn("all workers exited.");
    goto err_run;
err_run:
    return; // FIXME: stop workers, free structs
}

ssize_t mks5addr(uint8_t atyp, const char *host, in_port_t port, uint8_t **rslt) {
    if (atyp == ATYP_IP) {
        struct {
            struct in_addr addr;
            in_port_t port;
        } __attribute__((packed)) addr;

        int s = inet_pton(AF_INET, host, &(addr.addr));
        addr.port = port;
        if (s <= 0) {
            if (s == 0) log_fatal("inet_pton(): invalid ipv4 address.\n");
            if (s < 0) log_fatal("inet_pton(): %s\n", strerror(errno));
        }

        *rslt = malloc(sizeof(addr));
        memcpy(*rslt, &addr, sizeof(addr));
        return sizeof(addr);
    } else if (atyp == ATYP_IP6) {
        struct {
            struct in6_addr addr;
            in_port_t port;
        } __attribute__((packed)) addr;

        int s = inet_pton(AF_INET6, host, &(addr.addr));
        addr.port = port;
        if (s <= 0) {
            if (s == 0) log_fatal("inet_pton(): invalid ipv4 address.\n");
            if (s < 0) log_fatal("inet_pton(): %s\n", strerror(errno));
        }

        *rslt = malloc(sizeof(addr));
        memcpy(*rslt, &addr, sizeof(addr));
        return sizeof(addr);
    } else if (atyp == ATYP_FQDN) {
        size_t dlen = strlen(host);
        size_t buf_sz = 1 + dlen + sizeof(in_port_t); // 1: length field
        *rslt = malloc(buf_sz);
        *rslt[0] = dlen;
        memcpy((*rslt) + 1, host, dlen);
        (*(uint16_t *) (*rslt + dlen + 1)) = port;
        return buf_sz;
    } else {
        log_error("bad address type %d.\n", atyp);
        return -1;
    }

    log_fatal("unreached.\n");
    return -1;
}