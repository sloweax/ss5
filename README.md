## Usage
```
usage: ss5 [OPTION...]
OPTION:
     -h,--help                      shows usage and exits
     -v,--version                   shows version and exits
     -n,--no-auth                   allow NO AUTH
     -u,--userpass USER:PASS        add USER:PASS
     -U,--userpass-file FILE        add all user:pass from FILE
     -p,--port PORT                 listen on PORT (1080 by default)
     -a,--addr ADDR                 bind on ADDR (0.0.0.0 by default)
     -w,--workers WORKERS           number of WORKERS (4 by default)
```

## Build
Make sure you have `gcc` and `make` installed
```
git clone https://github.com/sloweax/ss5
cd ss5
make
```

## Supported socks5 features
- IPV4, IPV6, DOMAIN NAME Address types
- CONNECT command
- NO AUTH, multi USER:PASS authentication
- TCP
