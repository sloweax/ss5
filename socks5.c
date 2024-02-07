#include "socks5.h"
#include "ll.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int is_valid_cmd(S5Cmd cmd);
static int is_valid_atyp(S5Atyp atyp);
static int negotiate_auth_method(const S5ServerCtx *ctx, int fd, S5AuthMethod *method);
static int handle_auth_method(const S5ServerCtx *ctx, int fd, S5AuthMethod method);
static S5AuthMethod choose_auth_method(const S5ServerCtx *ctx, S5AuthMethod *methods, unsigned char nmethods);
static int auth_userpass(const S5ServerCtx *ctx, int fd);
static int bridge_fd(int fd1, int fd2);
static int connect_dst(struct sockaddr_storage *sa, int type, int proto);
static int resolve_atyp(int fd, S5Atyp *atyp, S5Rep *rep, struct sockaddr_storage *sa);
static int get_request(int fd, S5Cmd *cmd, S5Atyp *atyp, S5Rep *rep);
static int reply_request(int fd, S5Rep rep, S5Atyp atyp, struct sockaddr_storage *sa);

void s5_server_ctx_free(S5ServerCtx *ctx)
{
	char **data;
	LLNode *node = ctx->userpass->head;
	while (node) {
		data = node->data;
		free(data[0]);
		free(data[1]);
		free(data);
		node = node->next;
	}
	ll_free(ctx->userpass);
}

int s5_server_ctx_init(S5ServerCtx *ctx)
{
	ctx->flags = 0;
	ctx->userpass = ll_create();
	if (ctx->userpass == NULL) return 1;
	return 0;
}

int s5_server_add_userpass(S5ServerCtx *ctx, const char *user, const char *pass)
{
	size_t userlen, passlen;
	userlen = strlen(user);
	passlen = strlen(pass);
	if (userlen == 0 || passlen == 0 || userlen > 256 || passlen > 256) return 1;

	char **data;
	for (LLNode *node = ctx->userpass->head; node; node = node->next) {
		data = node->data;
		if (strcmp(data[0], user) == 0) return 2;
	}

	data = malloc(sizeof(char*)*2);
	if (data == NULL) return 1;

	data[0] = malloc(userlen + 1);
	if (data[0] == NULL) goto exit_free;
	memcpy(data[0], user, userlen+1);

	data[1] = malloc(passlen + 1);
	if (data[1] == NULL) goto exit_free_user;
	memcpy(data[1], pass, passlen+1);

	int r = ll_append(ctx->userpass, data);
	if (r != 0) goto exit_free_all;
	return r;

exit_free_all:
	free(data[1]);
exit_free_user:
	free(data[0]);
exit_free:
	free(data);
	return 1;
}

static int auth_userpass(const S5ServerCtx *ctx, int fd)
{
	char user[256 + 1];
	char pass[256 + 1];
	unsigned char len, ver, status = 1;

	if (read(fd, &ver, sizeof(ver)) != sizeof(ver)) return 1;
	if (read(fd, &len, sizeof(len)) != sizeof(len)) return 1;
	if (read(fd, user, len) != len) return 1;
	user[len] = 0;
	if (read(fd, &len, sizeof(len)) != sizeof(len)) return 1;
	if (read(fd, pass, len) != len) return 1;
	pass[len] = 0;

	char **data;
	LLNode *node = ctx->userpass->head;
	while (node) {
		data = node->data;
		if (strcmp(data[0], user) == 0 && strcmp(data[1], pass) == 0) {
			status = 0;
			break;
		}
		node = node->next;
	}

	if (ver != 1) status = 1;
	unsigned char buf[2];
	buf[0] = ver;
	buf[1] = status;
	if (write(fd, buf, sizeof(buf)) != sizeof(buf)) return 1;

	if (status != 0) {
		S5DLOGF("invalid user/password\n");
	}

	return status;
}

int s5_server_handler(const S5ServerCtx *ctx, int fd)
{
	S5AuthMethod method;

	if (negotiate_auth_method(ctx, fd, &method) != 0) {
		S5DLOGF("auth negotiation failed\n");
		return 1;
	}

	S5DLOGF("auth: %s\n", s5_auth_method_str(method));

	if (method == S5INVALID_AUTH_METHOD) return 0;

	int dstfd = -1;
	S5Cmd cmd;
	S5Atyp atyp;
	S5Rep rep;
	struct sockaddr_storage sa;

	if (get_request(fd, &cmd, &atyp, &rep) != 0) {
		S5DLOGF("get_request failed\n");
		return 1;
	}

	if (rep != S5REP_OK) goto reply;

	if (!is_valid_cmd(cmd))   rep = S5REP_CMD_NOT_SUPPORTED;
	if (!is_valid_atyp(atyp)) rep = S5REP_ATYP_NOT_SUPPORTED;

	if (rep != S5REP_OK) goto reply;

	if (resolve_atyp(fd, &atyp, &rep, &sa) != 0) {
		S5DLOGF("resolve_atyp failed\n");
		return 1;
	}

	if (rep != S5REP_OK) goto reply;

	errno = 0;
	dstfd = connect_dst(&sa, SOCK_STREAM, IPPROTO_TCP);
	if (dstfd == -1) {
		S5DLOGF("connect_dst failed\n");
		switch (errno) {
		case ENETUNREACH:
			rep = S5REP_NETWORK_UNREACHABLE;
			break;
		case ECONNREFUSED:
			rep = S5REP_CONNECTION_REFUSED;
			break;
		default:
			rep = S5REP_FAIL;
			break;
		}
	}

reply:

	S5DLOGF("replying: %s cmd: %s atyp: %s\n", s5_rep_str(rep), s5_cmd_str(cmd), s5_atyp_str(atyp));

	if (reply_request(fd, rep, atyp, &sa) != 0) {
		S5DLOGF("reply_request failed\n");
		goto exit_close_err;
	}

	if (rep != S5REP_OK) goto exit_close;
	if (dstfd == -1) return 1;

	int r = bridge_fd(fd, dstfd);

	S5DLOGF("connection %s\n", r == 0 ? "was succesfull" : "failed");

	close(dstfd);

	return r;

exit_close_err:
	if (dstfd != -1) close(dstfd);
	return 1;
exit_close:
	if (dstfd != -1) close(dstfd);
	return 0;
}

static int bridge_fd(int fd1, int fd2)
{
	char buf[4096];
	ssize_t rn1, rn2, wn1, wn2, lrn1, lrn2;

	lrn1 = lrn2 = 0;

	struct pollfd fds[2];

	fds[0].fd     = fd1;
	fds[0].events = POLLIN;
	fds[1].fd     = fd2;
	fds[1].events = POLLIN;

	while (1) {
		rn1 = rn2 = fds[0].revents = fds[1].revents = 0;

		int e = poll(fds, 2, 2000);
		if (e == -1) return 1;

		if ((fds[0].revents & (POLLHUP | POLLERR | POLLNVAL)) ||
		    (fds[1].revents & (POLLHUP | POLLERR | POLLNVAL)))
			return 1;

		if (fds[0].revents & POLLIN) {
			rn1 = read(fd1, buf, sizeof(buf));
			if (rn1 == -1) return 1;
			wn2 = write(fd2, buf, rn1);
			if (wn2 != rn1) return 1;
		}

		if (fds[1].revents & POLLIN) {
			rn2 = read(fd2, buf, sizeof(buf));
			if (rn2 == -1) return 1;
			wn1 = write(fd1, buf, rn2);
			if (wn1 != rn2) return 1;
		}

		if ((rn1 | lrn1 | rn2 | lrn2) == 0) return 0;

		lrn1 = rn1;
		lrn2 = rn2;
	}
}

static int is_valid_cmd(S5Cmd cmd)
{
	switch (cmd) {
	case S5CMD_CONNECT:
		return 1;
	default:
		return 0;
	}
}

static int is_valid_atyp(S5Atyp atyp)
{
	switch (atyp) {
	case S5ATYP_IPV4:
	case S5ATYP_IPV6:
	case S5ATYP_DOMAIN_NAME:
		return 1;
	default:
		return 0;
	}
}

char *s5_atyp_str(S5Atyp atyp)
{
	switch (atyp) {
	case S5ATYP_IPV4:        return "IPV4";
	case S5ATYP_IPV6:        return "IPV6";
	case S5ATYP_DOMAIN_NAME: return "Domain Name";
	default:                 return "?";
	}
}

char *s5_rep_str(S5Rep rep)
{
	switch (rep) {
	case S5REP_OK:                 return "OK";
	case S5REP_FAIL:               return "General Server Failure";
	case S5REP_ATYP_NOT_SUPPORTED: return "ATYP Not Supported";
	case S5REP_CMD_NOT_SUPPORTED:  return "CMD Not Supported";
	case S5REP_HOST_UNREACHABLE:   return "Host Unreachable";
	case S5REP_CONNECTION_REFUSED: return "Connection Refused";
	case S5REP_NETWORK_UNREACHABLE: return "Network Unreachable";
	default:                       return "?";
	}
}

char *s5_auth_method_str(S5AuthMethod method)
{
	switch (method) {
	case S5USERPASS_AUTH:       return "User:Pass Auth";
	case S5NO_AUTH:             return "No Auth";
	case S5INVALID_AUTH_METHOD: return "Invalid Auth Method";
	default:                    return "?";
	}
}

char *s5_cmd_str(S5Cmd cmd)
{
	switch (cmd) {
	case S5CMD_BIND:    return "BIND";
	case S5CMD_CONNECT: return "CONNECT";
	default:            return "?";
	}
}

static int connect_dst(struct sockaddr_storage *sa, int type, int proto)
{
	int fd = socket(sa->ss_family, type, proto);
	if (fd == -1) return -1;

	if (sa->ss_family == AF_INET) {
		if (connect(fd, (struct sockaddr *)sa, sizeof(struct sockaddr_in)) != 0) {
			close(fd);
			return -1;
		}
	} else {
		if (connect(fd, (struct sockaddr *)sa, sizeof(struct sockaddr_in6)) != 0) {
			close(fd);
			return -1;
		}
	}

	return fd;
}

static int reply_request(int fd, S5Rep rep, S5Atyp atyp, struct sockaddr_storage *sa)
{
	unsigned char buf[4 + 8 + 2], *tmp;
	tmp = buf;
	*tmp++ = 5; // version
	*tmp++ = rep;
	*tmp++ = 0; // reserved
	*tmp++ = atyp;

	switch (sa->ss_family) {
	case AF_INET:
		memcpy(tmp, &((struct sockaddr_in *)sa)->sin_addr, 4);
		tmp += 4;
		memcpy(tmp, &((struct sockaddr_in *)sa)->sin_port, 2);
		tmp += 2;
		break;
	case AF_INET6:
		memcpy(tmp, &((struct sockaddr_in6 *)sa)->sin6_addr, 8);
		tmp += 8;
		memcpy(tmp, &((struct sockaddr_in6 *)sa)->sin6_port, 2);
		tmp += 2;
		break;
	default:
		return 1;
	}

	return write(fd, buf, tmp - buf) == (tmp - buf) ? 0 : 1;
}

static int resolve_atyp(int fd, S5Atyp *atyp, S5Rep *rep, struct sockaddr_storage *sa)
{
	bzero(sa, sizeof(*sa));
	char host[257];
	unsigned char hostlen;
	struct addrinfo *ainfo, *tmp;
	*rep = S5REP_FAIL;

	switch (*atyp) {
	case S5ATYP_IPV4:
		sa->ss_family = AF_INET;
		if (read(fd, &((struct sockaddr_in *)sa)->sin_addr, 4) != 4) return 1;
		if (read(fd, &((struct sockaddr_in *)sa)->sin_port, 2) != 2) return 1;
		goto rep_ok;
	case S5ATYP_IPV6:
		sa->ss_family = AF_INET6;
		if (read(fd, &((struct sockaddr_in6 *)sa)->sin6_addr, 16) != 16) return 1;
		if (read(fd, &((struct sockaddr_in6 *)sa)->sin6_port, 2) != 2) return 1;
		goto rep_ok;
	case S5ATYP_DOMAIN_NAME:
		if (read(fd, &hostlen, sizeof(hostlen)) != sizeof(hostlen)) return 1;
		if (read(fd, host, hostlen) != hostlen) return 1;
		host[hostlen] = 0;
		if (getaddrinfo(host, NULL, NULL, &ainfo) != 0) return 1;

		tmp = ainfo;
		while (tmp) {
			if (tmp->ai_family == AF_INET6 || tmp->ai_family == AF_INET) break;
			tmp = tmp->ai_next;
		}

		if (tmp == NULL) {
			if (ainfo)
				freeaddrinfo(ainfo);
			*rep = S5REP_HOST_UNREACHABLE;
			return 0;
		}

		memcpy(sa, tmp->ai_addr, tmp->ai_addrlen);

		if (tmp->ai_family == AF_INET) {
			*atyp = S5ATYP_IPV4;
			if (read(fd, &((struct sockaddr_in *)sa)->sin_port, 2) != 2) goto free_error;
		} else {
			*atyp = S5ATYP_IPV6;
			if (read(fd, &((struct sockaddr_in6 *)sa)->sin6_port, 2) != 2) goto free_error;
		}
		goto free_rep_ok;
	default:
		*rep = S5REP_ATYP_NOT_SUPPORTED;
		return 0;
	}

free_rep_ok:
	freeaddrinfo(ainfo);
rep_ok:
	*rep = S5REP_OK;
	return 0;
free_error:
	freeaddrinfo(ainfo);
	return 1;
}

static int get_request(int fd, S5Cmd *cmd, S5Atyp *atyp, S5Rep *rep)
{
	*rep = S5REP_FAIL;
	unsigned char ver, rsv;

	if (read(fd, &ver, sizeof(ver)) != sizeof(ver)) return 1;
	if (read(fd, cmd, sizeof(*cmd)) != sizeof(*cmd)) return 1;
	if (read(fd, &rsv, sizeof(rsv)) != sizeof(rsv)) return 1;
	if (read(fd, atyp, sizeof(*atyp)) != sizeof(*atyp)) return 1;
	if (ver != 5) goto exit;
	*rep = S5REP_OK;
exit:
	S5DLOGF("request cmd: %s atyp: %s\n", s5_cmd_str(*cmd), s5_atyp_str(*atyp));
	return 0;
}

static S5AuthMethod choose_auth_method(const S5ServerCtx *ctx, S5AuthMethod *methods, unsigned char nmethods)
{
	if (ctx->flags & S5FLAG_NO_AUTH && memchr(methods, S5NO_AUTH, nmethods))
		return S5NO_AUTH;
	if (ctx->flags & S5FLAG_USERPASS_AUTH && memchr(methods, S5USERPASS_AUTH, nmethods))
		return S5USERPASS_AUTH;
	return S5INVALID_AUTH_METHOD;
}

static int handle_auth_method(const S5ServerCtx *ctx, int fd, S5AuthMethod method)
{
	switch (method) {
	case S5NO_AUTH:
		return 0;
	case S5USERPASS_AUTH:
		return auth_userpass(ctx, fd);
	default:
		return 1;
	}
}

static int negotiate_auth_method(const S5ServerCtx *ctx, int fd, S5AuthMethod *method)
{
	unsigned char buf[2 + 256];
	unsigned char ver, nmethods;
	S5AuthMethod smethod, *methods;

	if (read(fd, buf, sizeof(buf)) < 3) return 1;

	ver = buf[0];
	nmethods = buf[1];
	methods = &buf[2];

	if (ver != 5) return 1;

	smethod = choose_auth_method(ctx, methods, nmethods);

	buf[0] = ver;
	buf[1] = smethod;

	if (write(fd, buf, 2) != 2) return 1;

	if (handle_auth_method(ctx, fd, smethod) != 0)
		return 1;

	*method = smethod;

	return 0;
}

int s5_create_server(const char *host, const char *port, int backlog, int proto)
{
	struct addrinfo hints, *res;
	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_protocol = proto;
	hints.ai_flags = AI_PASSIVE;

	if (getaddrinfo(host, port, &hints, &res) != 0)
		return -1;

	int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sockfd == -1)
		goto error;

	if (bind(sockfd, res->ai_addr, res->ai_addrlen) != 0) {
		close(sockfd);
		sockfd = -1;
		goto error;
	}

	if (res->ai_socktype != SOCK_DGRAM && listen(sockfd, backlog) != 0) {
		close(sockfd);
		sockfd = -1;
		goto error;
	}

error:

	freeaddrinfo(res);
	return sockfd;
}
