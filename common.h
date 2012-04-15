#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void
error(const char *);

FILE *
ck_fopen(const char *, const char *);

void *
ck_malloc(size_t);

void
chomp(char *);

