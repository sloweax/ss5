#include "rfc1928.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

void socks5_handler(int fd)
{
	AuthMethod method;

	if (negotiate_auth_method(fd, &method) != 0) {
		DLOGF("auth negotiation failed\n");
		return;
	}

	DLOGF("method: %s\n", auth_method_str(method));

	if (method == INVALID_AUTH_METHOD) return;

	int dstfd = -1;
	Cmd cmd;
	Atyp atyp;
	Rep rep;
	struct sockaddr_storage sa;

	if (get_request(fd, &cmd, &atyp, &sa, &rep) != 0) {
		DLOGF("get_request failed\n");
		return;
	}

	DLOGF("cmd: %s atyp: %s\n", cmd_str(cmd), atyp_str(atyp));

	if (rep != REP_OK) goto reply;

	if (!is_valid_cmd(cmd))   rep = REP_CMD_NOT_SUPPORTED;
	if (!is_valid_atyp(atyp)) rep = REP_ATYP_NOT_SUPPORTED;

	if (rep != REP_OK) goto reply;

	errno = 0;
	dstfd = connect_dst(atyp, &sa, SOCK_STREAM, IPPROTO_TCP);
	if (dstfd == -1) {
		DLOGF("connect_dst failed\n");
		switch (errno) {
		case ENETUNREACH:
			rep = REP_NETWORK_UNREACHABLE;
		case ECONNREFUSED:
			rep = REP_CONNECTION_REFUSED;
		default:
			rep = REP_FAIL;
		}
	}

reply:

	DLOGF("replying: %s\n", rep_str(rep));

	if (reply_request(fd, rep, atyp, &sa) != 0) {
		DLOGF("reply failed\n");
		return;
	}

	if (dstfd == -1 || rep != REP_OK) return;

	bridge_fd(fd, dstfd);

	return;
}

void bridge_fd(int fd1, int fd2)
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
		if (e == -1) return;

		if ((fds[0].revents & (POLLHUP | POLLERR | POLLNVAL)) ||
		    (fds[1].revents & (POLLHUP | POLLERR | POLLNVAL)))
			return;

		if (fds[0].revents & POLLIN) {
			rn1 = read(fd1, buf, sizeof(buf));
			if (rn1 == -1) return;
			wn2 = write(fd2, buf, rn1);
			if (wn2 != rn1) return;
		}

		if (fds[1].revents & POLLIN) {
			rn2 = read(fd2, buf, sizeof(buf));
			if (rn2 == -1) return;
			wn1 = write(fd1, buf, rn2);
			if (wn1 != rn2) return;
		}

		if ((rn1 | lrn1 | rn2 | lrn2) == 0) return;

		lrn1 = rn1;
		lrn2 = rn2;
	}
}

int is_valid_cmd(Cmd cmd)
{
	switch (cmd) {
	case CMD_CONNECT:
		return 1;
	default:
		return 0;
	}
}

int is_valid_atyp(Atyp atyp)
{
	switch (atyp) {
	case ATYP_IPV4:
	case ATYP_IPV6:
	case ATYP_DOMAIN_NAME:
		return 1;
	default:
		return 0;
	}
}

char *atyp_str(Atyp atyp)
{
	switch (atyp) {
	case ATYP_IPV4:        return "IPV4";
	case ATYP_IPV6:        return "IPV6";
	case ATYP_DOMAIN_NAME: return "DOMAIN_NAME";
	default:               return "?";
	}
}

char *rep_str(Rep rep)
{
	switch (rep) {
	case REP_OK:                 return "OK";
	case REP_FAIL:               return "FAIL";
	case REP_ATYP_NOT_SUPPORTED: return "ATYP_NOT_SUPPORTED";
	case REP_CMD_NOT_SUPPORTED:  return "CMD_NOT_SUPPORTED";
	case REP_HOST_UNREACHABLE:   return "HOST_UNREACHABLE";
	case REP_CONNECTION_REFUSED: return "CONNECTION_REFUSED";
	default:                     return "?";
	}
}

char *auth_method_str(AuthMethod method)
{
	switch (method) {
	case NO_AUTH:             return "NO_AUTH";
	case INVALID_AUTH_METHOD: return "INVALID_AUTH_METHOD";
	default:                  return "?";
	}
}

char *cmd_str(Cmd cmd)
{
	switch (cmd) {
	case CMD_BIND:    return "BIND";
	case CMD_CONNECT: return "CONNECT";
	default:          return "?";
	}
}

int connect_dst(Atyp atyp, struct sockaddr_storage *sa, int type, int proto)
{
	switch (atyp) {
	case ATYP_IPV4:
	case ATYP_IPV6:
		break;
	default:
		return -1;
	}

	int fd = socket(sa->ss_family, type, proto);
	if (fd == -1) return -1;

	if (atyp == ATYP_IPV4) {
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

int reply_request(int fd, Rep rep, Atyp atyp, struct sockaddr_storage *sa)
{
	unsigned char ver = 5, rsv = 0;

	if (write(fd, &ver, sizeof(ver)) != sizeof(ver)) return 1;
	if (write(fd, &rep, sizeof(rep)) != sizeof(rep)) return 1;
	if (write(fd, &rsv, sizeof(rsv)) != sizeof(rsv)) return 1;
	if (write(fd, &atyp, sizeof(atyp)) != sizeof(atyp)) return 1;

	switch (sa->ss_family) {
	case AF_INET:
		if (write(fd, &((struct sockaddr_in *)sa)->sin_addr, 4) != 4) return 1;
		if (write(fd, &((struct sockaddr_in *)sa)->sin_port, 2) != 2) return 1;
		break;
	case AF_INET6:
		if (write(fd, &((struct sockaddr_in6 *)sa)->sin6_addr, 8) != 8) return 1;
		if (write(fd, &((struct sockaddr_in6 *)sa)->sin6_port, 2) != 2) return 1;
		break;
	default:
		return 1;
	}

	return 0;
}

int get_request(int fd, Cmd *cmd, Atyp *atyp, struct sockaddr_storage *sa, Rep *rep)
{
	*rep = REP_FAIL;
	bzero(sa, sizeof(*sa));
	struct addrinfo *ainfo, *tmp;
	unsigned char hostlen;
	char host[257] = { 0 };
	unsigned char ver, rsv;

	if (read(fd, &ver, sizeof(ver)) != sizeof(ver)) return 1;
	if (read(fd, cmd, sizeof(*cmd)) != sizeof(*cmd)) return 1;
	if (read(fd, &rsv, sizeof(rsv)) != sizeof(rsv)) return 1;
	if (read(fd, atyp, sizeof(*atyp)) != sizeof(*atyp)) return 1;
	if (ver != 5) return 0;

	switch (*atyp) {
	case ATYP_IPV4:
		sa->ss_family = AF_INET;
		if (read(fd, &((struct sockaddr_in *)sa)->sin_addr, 4) != 4) return 1;
		if (read(fd, &((struct sockaddr_in *)sa)->sin_port, 2) != 2) return 1;
		break;
	case ATYP_IPV6:
		sa->ss_family = AF_INET6;
		if (read(fd, &((struct sockaddr_in6 *)sa)->sin6_addr, 8) != 8) return 1;
		if (read(fd, &((struct sockaddr_in6 *)sa)->sin6_port, 2) != 2) return 1;
		break;
	case ATYP_DOMAIN_NAME:
		if (read(fd, &hostlen, sizeof(hostlen)) != sizeof(hostlen)) return 1;
		if (read(fd, host, hostlen) != hostlen) return 1;
		if (getaddrinfo(host, NULL, NULL, &ainfo) != 0) return 0;

		tmp = ainfo;
		while (tmp) {
			if (tmp->ai_family == AF_INET6 || tmp->ai_family == AF_INET) break;
			tmp = tmp->ai_next;
		}

		if (tmp == NULL) {
			freeaddrinfo(ainfo);
			return 0;
		}

		memcpy(sa, ainfo->ai_addr, ainfo->ai_addrlen);

		if (tmp->ai_family == AF_INET) {
			*atyp = ATYP_IPV4;
			if (read(fd, &((struct sockaddr_in *)sa)->sin_port, 2) != 2) {
				freeaddrinfo(ainfo);
				return 1;
			}
		} else {
			*atyp = ATYP_IPV6;
			if (read(fd, &((struct sockaddr_in6 *)sa)->sin6_port, 2) != 2) {
				freeaddrinfo(ainfo);
				return 1;
			}
		}

		freeaddrinfo(ainfo);
		break;
	default:
		*rep = REP_ATYP_NOT_SUPPORTED;
		return 0;
	}

	*rep = REP_OK;
	return 0;
}

AuthMethod choose_auth_method(AuthMethod *methods, unsigned char nmethods)
{
	if (memchr(methods, NO_AUTH, nmethods)) return NO_AUTH;
	return INVALID_AUTH_METHOD;
}

int handle_auth_method(int fd, AuthMethod method)
{
	switch (method) {
	case NO_AUTH:
		return 0;
	default:
		return 1;
	}
}

int negotiate_auth_method(int fd, AuthMethod *method)
{
	unsigned char ver, nmethods;
	AuthMethod methods[0xff], smethod;

	if (read(fd, &ver, sizeof(ver)) != sizeof(ver)) return 1;
	if (ver != 5) return 1;
	if (read(fd, &nmethods, sizeof(nmethods)) != sizeof(nmethods)) return 1;
	if (read(fd, methods, nmethods) != nmethods) return 1;

	smethod = choose_auth_method(methods, nmethods);

	if (write(fd, &ver, sizeof(ver)) != sizeof(ver)) return 1;
	if (write(fd, &smethod, sizeof(smethod)) != sizeof(smethod)) return 1;

	if (handle_auth_method(fd, smethod) != 0)
		return 1;

	*method = smethod;

	return 0;
}

int create_tcp_server(const char *host, const char *port, int backlog)
{
	struct addrinfo hints, *res;
	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if (getaddrinfo(host, port, &hints, &res) != 0)
		return -1;

	int sockfd = socket(res->ai_family, res->ai_socktype, IPPROTO_TCP);
	if (sockfd == -1)
		goto error;

	if (bind(sockfd, res->ai_addr, res->ai_addrlen) != 0) {
		close(sockfd);
		sockfd = -1;
		goto error;
	}

	if (listen(sockfd, backlog) != 0) {
		close(sockfd);
		sockfd = -1;
		goto error;
	}

error:

	freeaddrinfo(res);
	return sockfd;
}
