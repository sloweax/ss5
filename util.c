#include "util.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

FILE *efopen(const char *name, const char *mode)
{
	FILE *f = fopen(name, mode);
	if (f == NULL)
		die("fopen:");
	return f;
}

pid_t efork(void)
{
	pid_t pid = fork();
	if (pid == -1)
		die("fork:");
	return pid;
}

void *emalloc(size_t sz)
{
	void *p = malloc(sz);
	if (p == NULL)
		die("malloc:");
	return p;
}

void veprintf(const char *fmt, va_list ap)
{
	vfprintf(stderr, fmt, ap);
	if (fmt[0] && fmt[strlen(fmt) - 1] == ':') {
		fputc(' ', stderr);
		perror(NULL);
	} else {
		fputc('\n', stderr);
	}
}

void eprintf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	veprintf(fmt, ap);
	va_end(ap);
}

void die(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	veprintf(fmt, ap);
	va_end(ap);
	exit(1);
}
