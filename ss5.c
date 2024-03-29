#include "socks5.h"
#include "util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define VERSION "0.2.0"
#define PORT "1080"
#define ADDR "0.0.0.0"
#define BACKLOG 8
#define WORKERS 4

int nworkers = WORKERS;
pid_t *workers;
int run = 1;
int serverfd;
S5ServerCtx ctx;

static void cleanup()
{
	if (workers)
		free(workers);
	s5_server_ctx_free(&ctx);
	close(serverfd);
}

static void add_userpass(const char *userpass)
{
	char user[256 + 1];
	char pass[256 + 1];
	size_t userlen;
	size_t passlen;
	char *tmp = strchr(userpass, ':');

	if (tmp == NULL)
		die("user:pass `%s` is missing `:`", userpass);

	userlen = tmp - userpass;

	if (userlen == 0 || userlen >= sizeof(user))
		die("username length must be between 1-256");

	memcpy(user, userpass, userlen);
	user[userlen] = 0;
	tmp++;
	passlen = strlen(tmp);

	if (passlen == 0 || passlen >= sizeof(pass))
		die("password length must be between 1-256");

	pass[passlen] = 0;
	memcpy(pass, tmp, passlen);
	int r = s5_server_add_userpass(&ctx, user, pass);

	if (r == 2)
		die("user `%s` is already registered", user);

	if (r != 0)
		die("failed to add user:pass `%s`", userpass);
}

static void load_userpass_file(const char *filename)
{
	char *line = NULL;
	size_t len;
	ssize_t read;
	FILE *f = efopen(filename, "r");

	while ((read = getline(&line, &len, f)) != -1) {
		if (line[read - 1] == '\n') {
			line[read - 1] = 0;
			read--;
		}
		if (read == 0) continue;
		add_userpass(line);
	}

	if (errno)
		die("getline:");

	if (line) free(line);
	fclose(f);
}

static void int_handler(int sig)
{
	(void)sig;
	for (int i = 0; i < nworkers; i++)
		kill(workers[i], SIGINT);

	if (shutdown(serverfd, SHUT_RD) != 0)
		die("shutdown:");
}

static void worker_int_handler(int sig)
{
	(void)sig;
	if (nworkers == 1) {
		if (shutdown(serverfd, SHUT_RD) != 0)
			die("shutdown:");
	}
	run = 0;
}

static void weprintf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	if (nworkers != 1)
		fprintf(stderr, "worker %d: ", getpid());
	veprintf(fmt, ap);
	va_end(ap);
}

static int work()
{
	int r = 0;
	struct sockaddr_storage cli;
	socklen_t cli_len = sizeof(cli);

	if (signal(SIGINT, worker_int_handler) == SIG_ERR) {
		weprintf("signal:");
		if (nworkers != 1)
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
			weprintf("accept:");
			if (nworkers != 1)
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

	cleanup();

	return r;
}

static int create_worker()
{
	pid_t pid = efork();

	if (pid != 0)
		return pid;

	_Exit(work());
}

static void usage(int argc, char **argv)
{
	(void)argc;
	printf(
		"usage: %s [OPTION...]\n"
		"OPTION:\n"
		"     -h,--help                      shows usage and exits\n"
		"     -v,--version                   shows version and exits\n"
		"     -n,--no-auth                   allow NO AUTH\n"
		"     -u,--userpass USER:PASS        add USER:PASS\n"
		"     -U,--userpass-file FILE        add all user:pass from FILE\n"
		"     -p,--port PORT                 listen on PORT ("PORT" by default)\n"
		"     -a,--addr ADDR                 bind on ADDR ("ADDR" by default)\n"
		"     -w,--workers WORKERS           number of WORKERS (%d by default)\n"
	, argv[0], WORKERS);
}

int main(int argc, char **argv)
{
	setlinebuf(stdout);
	setlinebuf(stderr);

	char *addr = ADDR, *port = PORT;
	int opt;

	if (s5_server_ctx_init(&ctx) != 0)
		die("socks5_server_ctx_init:");

	static struct option long_options[] = {
		{"help"         , no_argument      , NULL, 'h'},
		{"version"      , no_argument      , NULL, 'v'},
		{"no-auth"      , no_argument      , NULL, 'n'},
		{"addr"         , required_argument, NULL, 'a'},
		{"port"         , required_argument, NULL, 'p'},
		{"userpass"     , required_argument, NULL, 'u'},
		{"userpass-file", required_argument, NULL, 'U'},
		{"workers"      , required_argument, NULL, 'w'},
		{NULL           , 0                , NULL, 0}
	};

	while((opt = getopt_long(argc, argv, ":hvna:p:u:U:w:", long_options, NULL)) != -1) {
		switch(opt) {
		case 'U':
			ctx.flags |= S5FLAG_USERPASS_AUTH;
			load_userpass_file(optarg);
			break;
		case 'u':
			ctx.flags |= S5FLAG_USERPASS_AUTH;
			add_userpass(optarg);
			break;
		case 'v':
			printf("%s %s\n", argv[0], VERSION);
			return 0;
			break;
		case 'w':
			nworkers = atoi(optarg);
			if (nworkers <= 0)
				die("%s %s is invalid", argv[optind-2], optarg, argv[0]);
			break;
		case 'n': ctx.flags |= S5FLAG_NO_AUTH; break;
		case 'a': addr = optarg; break;
		case 'p': port = optarg; break;
		case 'h':
			usage(argc, argv);
			return 0;
		case '?':
			die("unknown option %s\n%s -h for help", argv[optind-1], argv[0]);
		}
	}

	serverfd = s5_create_server(addr, port, BACKLOG, IPPROTO_TCP);
	if (serverfd == -1) {
		if (errno)
			die("could not create server:");
		else
			die("could not create server");
	}

	if (ctx.flags & S5FLAG_NO_AUTH)
		printf("accepting %s\n", s5_auth_method_str(S5NO_AUTH));

	if (ctx.flags & S5FLAG_USERPASS_AUTH)
		printf("accepting %s\n", s5_auth_method_str(S5USERPASS_AUTH));

	if (!(ctx.flags & (S5FLAG_NO_AUTH | S5FLAG_USERPASS_AUTH)))
		die("no auth method provided, exiting\n%s -h for help", argv[0]);

	printf("listening on %s:%s\n", addr, port);

	if (nworkers == 1) return work();

	workers = emalloc(nworkers * sizeof(pid_t));

	if (signal(SIGINT, int_handler) == SIG_ERR)
		die("signal:");

	pid_t pid;

	for (int i = 0; i < nworkers; i++) {
		pid = create_worker();
		workers[i] = pid;
		printf("starting worker %d\n", pid);
	}

	int child_exit_status, exit_status = 0;

	for (int i = 0; i < nworkers; i++) {
		pid = wait(&child_exit_status);
		printf("stopped worker %d exit status:%d\n", pid, WEXITSTATUS(child_exit_status));
		if (child_exit_status) exit_status = 1;
	}

	cleanup();

	return exit_status;
}
