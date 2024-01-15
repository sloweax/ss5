#pragma once

#include <stdio.h>
#include <sys/socket.h>

#define LOGF(...) printf(__VA_ARGS__)

#ifdef DEBUG
#define DLOGF(...) LOGF(__VA_ARGS__)
#else
#define DLOGF(...)
#endif

typedef unsigned char AuthMethod;
typedef unsigned char Cmd;
typedef unsigned char Atyp;
typedef unsigned char Rep;

enum AuthMethods {
	NO_AUTH             = 0,
	INVALID_AUTH_METHOD = 0xff,
};

enum Cmds {
	CMD_CONNECT       = 1,
	CMD_BIND          = 2,
	CMD_UDP_ASSOCIATE = 3,
};

enum Atyps {
	ATYP_IPV4         = 1,
	ATYP_DOMAIN_NAME  = 3,
	ATYP_IPV6         = 4,
};

enum Reps {
	REP_OK                  = 0,
	REP_FAIL                = 1,
	REP_NETWORK_UNREACHABLE = 3,
	REP_HOST_UNREACHABLE    = 4,
	REP_CONNECTION_REFUSED  = 5,
	REP_CMD_NOT_SUPPORTED   = 7,
	REP_ATYP_NOT_SUPPORTED  = 8,
};

void socks5_handler(int fd);

int create_tcp_server(const char *host, const char *port, int backlog);
void bridge_fd(int fd1, int fd2);

AuthMethod choose_auth_method(AuthMethod *methods, unsigned char nmethods);
int negotiate_auth_method(int fd, AuthMethod *method);
int handle_auth_method(int fd, AuthMethod method);

int get_request(int fd, Cmd *cmd, Atyp *atyp, struct sockaddr_storage *sa, Rep *rep);
int reply_request(int fd, Rep rep, Atyp atyp, struct sockaddr_storage *sa);
int connect_dst(Atyp atyp, struct sockaddr_storage *sa, int type, int proto);

int is_valid_cmd(Cmd cmd);
int is_valid_atyp(Atyp atyp);

char *atyp_str(Atyp atyp);
char *cmd_str(Cmd cmd);
char *rep_str(Rep rep);
char *auth_method_str(AuthMethod method);
