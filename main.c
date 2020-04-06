#include "s5tunnel.h"
#include "socks5.h"
#include "log.h"
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

bool parse_tunnel(const char *s, s5_remote_t **remote, int proto) {
    char *str = strdup(s);

    if (!str) {
        log_error("strdup(): %s\n", strerror(errno));
        return false;
    }

    char *tkn, *lhost, *lport, *atyp, *rhost, *rport;
    tkn = lhost = lport = atyp = rhost = rport = NULL;
    tkn = strtok(str, ",");
    bool ok = false;
    uint8_t atyp_i = 0xff;

    int pos = 0;
    while (tkn) {
        /**/ if (pos == 0) lhost = strdup(tkn);
        else if (pos == 1) lport = strdup(tkn);
        else if (pos == 2) atyp = strdup(tkn);
        else if (pos == 3) rhost = strdup(tkn);
        else if (pos == 4) rport = strdup(tkn);
        else {
            log_error("too many options for tunnel specification: %s\n", s);
            goto parse_end;
        }
        tkn = strtok(NULL, ",");
        pos++;
    }

    if (pos != 5) {
        log_error("not enough options for tunnel specification: %s\n", s);
        goto parse_end;
    }

    if (strcmp(atyp, "ip") == 0) atyp_i = ATYP_IP;
    if (strcmp(atyp, "ip6") == 0) atyp_i = ATYP_IP6;
    if (strcmp(atyp, "fqdn") == 0) atyp_i = ATYP_FQDN;
    if (atyp_i == 0xff) {
        log_error("bad remote address type: %s\n", atyp);
        goto parse_end;
    }

    *remote = (s5_remote_t *) malloc(sizeof(s5_remote_t));
    ssize_t sz = mks5addr(atyp_i, rhost, htons(atoi(rport)), &((*remote)->remote)); // FIXME: atoi
    if (sz < 0) {
        log_error("error creating remote address.\n");
        free(*remote);
        goto parse_end;
    }

    (*remote)->local_host = lhost;
    (*remote)->local_port = lport;
    (*remote)->remote_type = atyp_i;
    (*remote)->remote_len = sz;
    (*remote)->protocol = proto;
    (*remote)->next = NULL;
    ok = true;

parse_end:
    if (str) free(str);
    if (!ok && lhost) free(lhost);
    if (!ok && lport) free(lport);
    if (atyp) free(atyp);
    if (rhost) free(rhost);
    if (rport) free(rport);
    return ok;
}

void help() {
    fprintf(stderr, "usage: s5tunnel -s SERVER_HOST -p SERVER_PORT [-U USER -P PASS] TSPEC [TSPEC...]\n");
    fprintf(stderr, "where: TSPEC := PROTO LADDR,LPORT,RTYPE,RADDR,RPORT\n");
    fprintf(stderr, "       PROTO := { -t | -u }\n");
    fprintf(stderr, "       RTYPE := { ip | ip6 | fqdn }\n");
}

void freeconfig(s5_config_t *cfg) {
    if (cfg->server_host) free(cfg->server_host);
    if (cfg->server_port) free(cfg->server_port);
    if (cfg->user) free(cfg->user);
    if (cfg->passwd) free(cfg->passwd);

    for (s5_remote_t *r = cfg->remotes; r != NULL; ) {
        if (r->local_host) free(r->local_host);
        if (r->local_port) free(r->local_port);
        if (r->remote) free(r->remote);
        s5_remote_t *lst = r;
        r = r->next;
        free(lst);
    }
}

int main (int argc, char **argv) {
    s5_config_t cfg;
    memset(&cfg, 0, sizeof(s5_config_t));
    s5_remote_t *r = cfg.remotes;

    int c;

    while ((c = getopt(argc, argv, "s:p:U:P:t:u:")) != -1) {
        switch (c) {
            case 's': cfg.server_host = strdup(optarg); break;
            case 'p': cfg.server_port = strdup(optarg); break;
            case 'U': cfg.auth_enabled = true; cfg.user = strdup(optarg); break;
            case 'P': cfg.auth_enabled = true; cfg.passwd = strdup(optarg); break;
            case 't':
            case 'u': {
                int proto = c == 'u' ? IPPROTO_UDP : IPPROTO_TCP;
                s5_remote_t *_r;
                if (!parse_tunnel(optarg, &_r, proto)) {
                    help();
                    goto err;
                }
                if (r == NULL) r = cfg.remotes = _r;
                else {
                    r->next = _r;
                    r = _r;
                }
            }
        }
    }
    
    if (cfg.server_host == NULL || cfg.server_port == NULL || (cfg.auth_enabled && (cfg.passwd == NULL || cfg.user == NULL)) || cfg.remotes == NULL) {
        help();
        goto err;
    }

    s5_run(&cfg);

err:
    freeconfig(&cfg);
    return 1;
}