## Usage
```
usage: ./socks5-server [OPTION]...
OPTION:
     -h                  shows usage and exits
     -n                  allow NO AUTH
     -u user:pass        add user:pass
     -U file             add all user:pass from file
     -p port             listen on port (1080 by default)
     -l host             listen on host (0.0.0.0 by default)
```

## Build
Make sure you have `gcc` and `make` installed
```
git clone https://github.com/sloweax/socks5-server
cd socks5-server
make
```

## Supported socks5 features
- IPV4, IPV6, DOMAIN NAME Address types
- CONNECT command
- NO AUTH, multi USER:PASS authentication
- TCP
