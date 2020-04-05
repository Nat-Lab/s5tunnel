#include "s5tunnel.h"
#include "socks5.h"
#include "log.h"
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>

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
    hints.ai_flags = AI_DEFAULT;
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

int s5_new_connection(const s5_config_t *config, const s5_remote_t *remote) {
    int fd = gai_connect(config->server_host, config->server_port, SOCK_STREAM, IPPROTO_TCP);

    s5_method_request_t mreq;
    mreq.ver = SOCK_VER;
    mreq.nmethods = 1;
    mreq.methods = config->auth_enabled ? S5_AUTH_USER_PASSWD : S5_AUTH_NONE;
    ssize_t sz = write(fd, &mreq, sizeof(s5_method_request_t));
    if (sz < 0) {
        log_fatal("write(): %s\n", strerror(errno));
        goto err;
    }

    static int state = METHOD_SENT;
    uint8_t buffer[128];
    uint8_t send_buffer[128];

    while (1) {
        ssize_t len = read(fd, buffer, sizeof(buffer));
        if (len < 0) {
            log_fatal("read(): %s\n", strerror(errno));
            goto err;
        }

        if (state == METHOD_SENT) {
            if (len != sizeof(s5_method_reply_t)) {
                log_fatal("bad s5_method_reply message.\n");
                goto err;
            }

            s5_method_reply_t *reply = (s5_method_reply_t *) buffer;

            if (reply->ver != SOCK_VER) {
                log_fatal("bad remote server version: %d.\n", reply->ver);
                goto err;
            }

            if (reply->method == S5_AUTH_BAD) {
                log_fatal("remote: bad auth.\n");
                goto err;
            }

            if (reply->method != S5_AUTH_NONE && reply->method != S5_AUTH_USER_PASSWD) {
                log_fatal("unknow server auth method: %d.\n", reply->method);
                goto err;
            }

            if ((reply->method == S5_AUTH_USER_PASSWD) == config->auth_enabled) {
                log_fatal("bad server auth method: %d.\n", reply->method);
                goto err;
            }

            if (reply->method == S5_AUTH_NONE) {
                state = AUTH_SENT;
                continue;
            }

            if (reply->method == S5_AUTH_USER_PASSWD) {
                /** todo **/
            }
        }

        if (state == AUTH_SENT) {
            if (config->auth_enabled) {
                /** todo **/
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
                goto err;
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
                goto err;
            }

            if (reply->rep != REP_OK) {
                log_fatal("remote request rejected: %d.\n", reply->rep);
                goto err;
            }
            
            if (remote->protocol == IPPROTO_UDP) {
                /** todo **/
            }

            return fd;
        }
    }

err:
    close(fd);
    return -1;
}