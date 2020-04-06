#ifndef S5_SOCKS5_H
#define S5_SOCKS5_H
#include <stdint.h>

#define SOCK_VER 0x05

#define S5_AUTH_NONE 0x00
#define S5_AUTH_USER_PASSWD 0x02
#define S5_AUTH_BAD 0xff

typedef struct s5_method_request {
    uint8_t ver;
    uint8_t nmethods; // always 1 in our case
    uint8_t methods; // S5_AUTH_NONE or S5_AUTH_USER_PASSWD
} __attribute__((packed)) s5_method_request_t;

typedef struct s5_method_reply {
    uint8_t ver;
    uint8_t method;
} __attribute__((packed)) s5_method_reply_t;

#define CMD_CONNECT 0x01
#define CMD_BIND 0x02
#define CMD_UDP_ASSOC 0x03

#define ATYP_IP 0x01
#define ATYP_FQDN 0x03
#define ATYP_IP6 0x04

typedef struct s5_request_hdr {
    uint8_t ver;
    uint8_t cmd;
    uint8_t rsv;
    uint8_t atyp;
} __attribute__((packed)) s5_request_hdr_t;

#define REP_OK 0x00
#define REP_GENERAL 0x01
#define REP_DENY 0x02
#define REP_NET_UNREACH 0x03
#define REP_HOST_UNREACH 0x04
#define REP_CONN_REFUSED 0x05
#define REP_TTL_EXPIRED 0x06
#define REP_BAD_COMMAND 0x07
#define REP_BAD_ATYP 0x08

typedef struct s5_reply_hdr {
    uint8_t ver;
    uint8_t rep;
    uint8_t rsv;
    uint8_t atyp;
} __attribute__((packed)) s5_reply_hdr_t;

typedef struct s5_udp_payload_hdr {
    uint16_t rsv;
    uint8_t frag;
    uint8_t atyp;
} __attribute__((packed)) s5_udp_payload_hdr_t;

#endif // S5_SOCKS5_H