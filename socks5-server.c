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
#define HOST "0.0.0.0"
#define BACKLOG 8

int run = 1;
int serverfd;

void int_handler(int sig)
{
	(void)sig;
	if (shutdown(serverfd, SHUT_RD) == -1)
		die("shutdown:");
	run = 0;
}

int main(int argc, char **argv)
{
	Socks5ServerCtx ctx;
	char *host = HOST, *port = PORT;
	int opt;

	if (socks5_server_ctx_init(&ctx) != 0)
		die("socks5_server_ctx_init:");

	while((opt = getopt(argc, argv, ":l:p:hnu:U:")) != -1) {
		switch(opt) {
		case 'U':
			{
				ctx.flags |= FLAG_USERPASS_AUTH;
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
					if (socks5_server_add_userpass(&ctx, line) != 0)
						die("socks5_server_add_userpass:");
				}

				if (line) free(line);
				fclose(uf);
			}
			break;
		case 'u':
			ctx.flags |= FLAG_USERPASS_AUTH;
			if (socks5_server_add_userpass(&ctx, optarg) != 0)
				die("socks5_server_add_userpass:");
			break;
		case 'n': ctx.flags |= FLAG_NO_AUTH; break;
		case 'l': host = optarg; break;
		case 'p': port = optarg; break;
		case 'h':
			die(
				"usage: %s [OPTION]...\n"
				"OPTION:\n"
				"     -h                  shows usage and exits\n"
				"     -n                  allow NO AUTH\n"
				"     -u user:pass        add user:pass\n"
				"     -U file             add all user:pass from file\n"
				"     -p port             listen on port ("PORT" by default)\n"
				"     -l host             listen on host ("HOST" by default)"
			, argv[0]);
		case '?':
			die("unknown option -%c\n%s -h for help", optopt, argv[0]);
		}
	}

	if (signal(SIGINT, int_handler) == SIG_ERR ||
		signal(SIGCHLD, SIG_IGN)    == SIG_ERR)
		die("signal:");

	serverfd = create_tcp_server(host, port, BACKLOG);
	if (serverfd == -1)
		die("could not create server");

	if (ctx.flags & FLAG_NO_AUTH)
		printf("accepting %s\n", auth_method_str(NO_AUTH));

	if (ctx.flags & FLAG_USERPASS_AUTH)
		printf("accepting %s\n", auth_method_str(USERPASS_AUTH));

	if (!(ctx.flags & (FLAG_NO_AUTH | FLAG_USERPASS_AUTH)))
		die("no auth method provided, exiting\n%s -h for help", argv[0]);

	printf("listening on %s:%s\n", host, port);

	struct sockaddr_storage cli;
	socklen_t cli_len = sizeof(cli);

	while (run) {
		int cfd = accept(serverfd, (struct sockaddr *)&cli, &cli_len);

		if (!run) {
			if (cfd != -1)
				close(cfd);
			break;
		}

		if (cfd == -1)
			die("accept:");

		int pid = fork();

		if (pid == -1)
			die("fork:");

		if (pid == 0) {
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

			if (signal(SIGINT, SIG_DFL) == SIG_ERR)
				die("signal:");

			close(serverfd);

			socks5_handler(&ctx, cfd);

			close(cfd);

			socks5_ctx_free(&ctx);

			exit(0);
		} else {
			close(cfd);
		}
	}

	while (wait(NULL) > 0);

	close(serverfd);
	socks5_ctx_free(&ctx);

	return 0;
}
