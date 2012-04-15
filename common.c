#include "common.h"

void
error(const char * msg)
{
  perror(msg);
  exit(EXIT_FAILURE);
}

FILE *
ck_fopen(const char * path, const char * mode)
{
  FILE * file = fopen(path, mode);
  if (file == NULL) 
    error("fopen");
  return file;
}

void *
ck_malloc(size_t size)
{
  void * ptr = malloc(size);
  if (ptr == NULL) 
    error("malloc");
  return ptr;
}

void
chomp(char * str)
{
  while (*str) {
    if (*str == '\n' || *str == '\r') {
      *str = 0;
      return;
    }
    str++;
  }
}
