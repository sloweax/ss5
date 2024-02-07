#pragma once

#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

void eprintf(const char *fmt, ...);
void veprintf(const char *fmt, va_list ap);
void die(const char *fmt, ...);
FILE *efopen(const char *name, const char *mode);
void *emalloc(size_t sz);
pid_t efork(void);
