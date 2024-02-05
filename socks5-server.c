#include "rfc1928.h"
#include "util.h"
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define PORT "1080"
#define ADDR "0.0.0.0"
#define BACKLOG 8
#define WORKERS 4

int nworkers = WORKERS;
pid_t *workers;
int run = 1;
int serverfd;
S5ServerCtx ctx;

static int add_userpass(char *userpass)
{
	char user[256 + 1];
	char pass[256 + 1];
	size_t userlen;
	size_t passlen;
	char *tmp = strchr(userpass, ':');
	if (tmp == NULL) return 1;
	userlen = tmp - userpass;
	if (userlen >= sizeof(user)) return 1;
	memcpy(user, userpass, userlen);
	user[userlen] = 0;
	tmp++;
	passlen = strlen(tmp);
	if (passlen == 0 || passlen >= sizeof(pass)) return 1;
	pass[passlen] = 0;
	memcpy(pass, tmp, passlen);
	return s5_server_add_userpass(&ctx, user, pass);
}

void int_handler(int sig)
{
	(void)sig;
	for (int i = 0; i < nworkers; i++)
		kill(workers[i], SIGINT);

	if (shutdown(serverfd, SHUT_RD) != 0)
		die("shutdown:");
}

void worker_int_handler(int sig)
{
	(void)sig;
	run = 0;
}

int create_worker()
{
	int r = 0;
	pid_t pid = fork();

	if (pid == -1)
		die("fork:");

	if (pid != 0)
		return pid;

	struct sockaddr_storage cli;
	socklen_t cli_len = sizeof(cli);

	if (signal(SIGINT, worker_int_handler) == SIG_ERR) {
		fprintf(stderr, "worker %d: signal: ", getpid());
		perror(NULL);
		kill(getppid(), SIGINT);
		r = 1;
		goto exit;
	}

	while (run) {
		int cfd = accept(serverfd, (struct sockaddr *)&cli, &cli_len);

		if (!run) {
			if (cfd != -1)
				close(cfd);
			break;
		}

		if (cfd == -1) {
			fprintf(stderr, "worker %d: accept: ", getpid());
			perror(NULL);
			kill(getppid(), SIGINT);
			r = 1;
			goto exit;
		}

		char clihost[INET6_ADDRSTRLEN];
		clihost[0] = 0;

		switch (cli.ss_family) {
		case AF_INET:
			inet_ntop(cli.ss_family, &((struct sockaddr_in *)&cli)->sin_addr, clihost, sizeof(clihost));
			break;
		case AF_INET6:
			inet_ntop(cli.ss_family, &((struct sockaddr_in6 *)&cli)->sin6_addr, clihost, sizeof(clihost));
			break;
		}

		printf("connection from %s\n", clihost);

		s5_server_handler(&ctx, cfd);

		close(cfd);
	}

exit:

	printf("stopped worker %d\n", getpid());

	free(workers);
	close(serverfd);
	s5_server_ctx_free(&ctx);
	_Exit(r);
}

void usage(int argc, char **argv)
{
	(void)argc;
	printf(
		"usage: %s [OPTION]...\n"
		"OPTION:\n"
		"     -h                  shows usage and exits\n"
		"     -n                  allow NO AUTH\n"
		"     -u user:pass        add user:pass\n"
		"     -U file             add all user:pass from file\n"
		"     -p port             listen on port ("PORT" by default)\n"
		"     -a addr             bind on addr ("ADDR" by default)\n"
		"     -w workers          number of workers (%d by default)\n"
	, argv[0], WORKERS);
}

int main(int argc, char **argv)
{
	char *addr = ADDR, *port = PORT;
	int opt;

	if (s5_server_ctx_init(&ctx) != 0)
		die("socks5_server_ctx_init:");

	while((opt = getopt(argc, argv, ":a:p:hnu:U:w:")) != -1) {
		switch(opt) {
		case 'U':
			{
				ctx.flags |= S5FLAG_USERPASS_AUTH;
				char *line = NULL;
				size_t len;
				ssize_t read;
				FILE *uf = fopen(optarg, "r");
				if (uf == NULL)
					die("fopen:");

				while ((read = getline(&line, &len, uf)) != -1) {
					if (line[read - 1] == '\n') {
						line[read - 1] = 0;
						read--;
					}
					if (read == 0) continue;
					if (add_userpass(line) != 0)
						die("socks5_server_add_userpass:");
				}

				if (line) free(line);
				fclose(uf);
			}
			break;
		case 'u':
			ctx.flags |= S5FLAG_USERPASS_AUTH;
			if (add_userpass(optarg) != 0)
				die("socks5_server_add_userpass:");
			break;
		case 'w':
			nworkers = atoi(optarg);
			if (nworkers <= 0)
				die("`-w %s` is invalid\n%s -h for help", optarg, argv[0]);
			break;
		case 'n': ctx.flags |= S5FLAG_NO_AUTH; break;
		case 'a': addr = optarg; break;
		case 'p': port = optarg; break;
		case 'h':
			usage(argc, argv);
			return 0;
		case '?':
			die("unknown option -%c\n%s -h for help", optopt, argv[0]);
		}
	}

	workers = malloc(nworkers * sizeof(pid_t));
	if (workers == NULL)
		die("malloc:");

	serverfd = s5_create_server(addr, port, BACKLOG, IPPROTO_TCP);
	if (serverfd == -1)
		die("could not create server");

	if (ctx.flags & S5FLAG_NO_AUTH)
		printf("accepting %s\n", s5_auth_method_str(S5NO_AUTH));

	if (ctx.flags & S5FLAG_USERPASS_AUTH)
		printf("accepting %s\n", s5_auth_method_str(S5USERPASS_AUTH));

	if (!(ctx.flags & (S5FLAG_NO_AUTH | S5FLAG_USERPASS_AUTH)))
		die("no auth method provided, exiting\n%s -h for help", argv[0]);

	printf("listening on %s:%s\n", addr, port);

	if (signal(SIGINT, int_handler) == SIG_ERR)
		die("signal:");

	for (int i = 0; i < nworkers; i++) {
		pid_t pid = create_worker();
		workers[i] = pid;
		printf("starting worker %d\n", pid);
	}

	s5_server_ctx_free(&ctx);

	for (int i = 0; i < nworkers; i++)
		wait(NULL);

	close(serverfd);
	free(workers);

	return 0;
}
