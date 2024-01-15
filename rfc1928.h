#pragma once

#include "ll.h"
#include <stdio.h>
#include <sys/socket.h>

#define S5LOGF(...) printf(__VA_ARGS__)

#ifdef S5DEBUG
#define S5DLOGF(...) S5LOGF(__VA_ARGS__)
#else
#define S5DLOGF(...)
#endif

typedef unsigned char S5AuthMethod;
typedef unsigned char S5Cmd;
typedef unsigned char S5Atyp;
typedef unsigned char S5Rep;

struct S5ServerCtx {
	LL *userpass;
	int flags;
};

typedef struct S5ServerCtx S5ServerCtx;

enum S5ServerFlags {
	S5FLAG_NO_AUTH = 1 << 0,
	S5FLAG_USERPASS_AUTH = 1 << 1,
};

enum S5AuthMethods {
	S5NO_AUTH             = 0,
	S5USERPASS_AUTH       = 2,
	S5INVALID_AUTH_METHOD = 0xff,
};

enum S5Cmds {
	S5CMD_CONNECT       = 1,
	S5CMD_BIND          = 2,
	S5CMD_UDP_ASSOCIATE = 3,
};

enum S5Atyps {
	S5ATYP_IPV4         = 1,
	S5ATYP_DOMAIN_NAME  = 3,
	S5ATYP_IPV6         = 4,
};

enum S5Reps {
	S5REP_OK                  = 0,
	S5REP_FAIL                = 1,
	S5REP_NETWORK_UNREACHABLE = 3,
	S5REP_HOST_UNREACHABLE    = 4,
	S5REP_CONNECTION_REFUSED  = 5,
	S5REP_CMD_NOT_SUPPORTED   = 7,
	S5REP_ATYP_NOT_SUPPORTED  = 8,
};

// int functions below return 0 on success
int s5_server_ctx_init(S5ServerCtx *ctx);
void s5_server_ctx_free(S5ServerCtx *ctx);
int s5_server_add_userpass(S5ServerCtx *ctx, char *userpass);
int s5_server_handler(const S5ServerCtx *ctx, int fd);

// returns -1 on error
int s5_create_server(const char *host, const char *port, int backlog, int proto);

char *s5_atyp_str(S5Atyp atyp);
char *s5_cmd_str(S5Cmd cmd);
char *s5_rep_str(S5Rep rep);
char *s5_auth_method_str(S5AuthMethod method);
