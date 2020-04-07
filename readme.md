s5tunnel
---

`s5tunnel` is a simple tool that tunnels local TCP/UDP ports to remote servers through a SOCKS5 proxy.

### Usage

```
usage: s5tunnel -s SERVER_HOST -p SERVER_PORT [-U USER -P PASS] TSPEC [TSPEC...]
where: TSPEC := PROTO LADDR,LPORT,RTYPE,RADDR,RPORT
       PROTO := { -t | -u }
       RTYPE := { ip | ip6 | fqdn }
```

For example, the following command:

```
$ ./s5tunnel -s 127.0.0.1 -p 1080 \
    -t 0.0.0.0,9090,ip,202.5.31.222,80 \
    -t 0.0.0.0,9091,ip6,2602:feda:4::3,80 \
    -t ::,2200,ip,202.5.31.222,22 \
    -t 0.0.0.0,9092,fqdn,nat.moe,80 \
    -u 0.0.0.0,9053,ip,202.5.31.222,53
```

creates five tunnels through SOCKS5 server on `127.0.0.1:1080`:

local|remote
--|--
`0.0.0.0:9090/tcp`|`202.5.31.222:80/tcp`
`0.0.0.0:9091/tcp`|`[2602:feda:4::3]:80/tcp`
`[::]:2200/tcp`|`202.5.31.222:22/tcp`
`0.0.0.0:9092/tcp`|`nat.moe:80/tcp`
`0.0.0.0:9053/udp`|`202.5.31.222:43/udp`

### Installation

```
$ git clone https://github.com/nat-lab/s5tunnel
$ cd s5tunnel
$ make
```

### License

UNLICENSE