/*
DNS Discovery
  A multithreaded subdomain bruteforcer

googlecode : http://dns-discovery.googlecode.com

author	   : Victor Ramos Mello aka m0nad
email	   : m0nad /at/ email.com
github	   : https://github.com/m0nad/
copyfree   : beer license, if you like this, buy me a beer
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#define LEN 256
#define MAX 512
#define DEFAULT_WL "wordlist.wl"

#define SAY(args...)\
  printf (args);\
  if (dd_args.report)\
    fprintf (dd_args.report, args);

struct dns_discovery_args {
  FILE * report;
  FILE * csv;
  char * domain;
  int nthreads;
};
struct dns_discovery_args dd_args;
pthread_mutex_t mutexsum;

void
error (const char * msg)
{
  perror (msg);
  exit (1);
}

FILE *
ck_fopen (const char * path, const char * mode)
{
  FILE * file = fopen (path, mode);
  if (file == NULL) 
    error ("fopen");
  return file;
}

void *
ck_malloc (size_t size)
{
  void * ptr = malloc (size);
  if (ptr == NULL) 
    error ("malloc");
  return ptr;
}

void
chomp (char * str)
{
  while (*str) {
    if (*str == '\n' || *str == '\r') {
      *str = 0;
      return;
    }
    str++;
  }
}

void
banner ()
{
  SAY ("   ___  _  ______    ___  _                              \n"
       "  / _ \\/ |/ / __/___/ _ \\(_)__ _______ _  _____ ______ __\n"
       " / // /    /\\ \\/___/ // / (_-</ __/ _ \\ |/ / -_) __/ // /\n"
       "/____/_/|_/___/   /____/_/___/\\__/\\___/___/\\__/_/  \\_, / \n"
       "                                                  /___/  \n"
       "\tby m0nad\n\n");
}

int
usage ()
{
  SAY ("usage: ./dns-discovery <domain> [options]\n"
       "options:\n"
       "\t-w <wordlist file> (default : %s)\n"
       "\t-t <threads> (default : 1)\n"
       "\t-r <report file>\n"
       "\t-c <csv report file>\n\n", DEFAULT_WL);
  exit (0);
}

FILE *
parse_args (int argc, char ** argv)
{
  FILE * wordlist = NULL;
  char c, * ptr_wl = DEFAULT_WL; 
  if (argc < 2) 
    usage ();
  dd_args.domain = argv[1];
  dd_args.nthreads = 1;
  printf ("DOMAIN: %s\n", dd_args.domain);
  argc--;
  argv++;
  opterr = 0;
  while ((c = getopt (argc, argv, "r:w:t:c:")) != -1)
    switch (c) {
      case 'w':
        ptr_wl = optarg;
        printf ("WORDLIST: %s\n", optarg);
        wordlist = ck_fopen (optarg, "r");
        break;
      case 't':
        printf ("THREADS: %s\n", optarg);
        dd_args.nthreads = atoi (optarg);
	break;
      case 'r':
        printf ("REPORT: %s\n", optarg);
        dd_args.report = ck_fopen (optarg, "w");
        break;
      case 'c':
        printf ("CSV REPORT: %s\n", optarg);
        dd_args.csv = ck_fopen (optarg, "w");
        break;
      case '?':
        if (optopt == 'r' || optopt == 'w' || optopt == 't') {
          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
	  exit (1);
        }
      default:
        usage ();
    }
  printf ("WORDLIST: %s\n", ptr_wl);
  wordlist = ck_fopen (ptr_wl, "r");

  printf ("\n");

  return wordlist;
}

void
resolve_lookup (const char * hostname)
{
  int ipv = 0;
  char addr_str [LEN];
  void * addr_ptr = NULL;
  struct addrinfo * res, * ori_res, hints;

  memset (&hints, 0, sizeof hints);
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags |= AI_CANONNAME;

  if (getaddrinfo (hostname, NULL, &hints, &res) == 0) {
    pthread_mutex_lock (&mutexsum);
    SAY ("%s\n", hostname);
    if (dd_args.csv)
      fprintf (dd_args.csv, "%s", hostname);
    for (ori_res = res; res; res = res->ai_next) { 
      switch (res->ai_family) {
        case AF_INET:
          ipv = 4;
          addr_ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
          break;
        case AF_INET6:
          ipv = 6;
          addr_ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
          break;
      }
      inet_ntop (res->ai_family, addr_ptr, addr_str, LEN);
      SAY ("IPv%d address: %s\n", ipv, addr_str);
      if (dd_args.csv)
	fprintf (dd_args.csv, ",%s", addr_str);
    }
    SAY ("\n");
    if (dd_args.csv)
       fprintf (dd_args.csv, "\n");
    pthread_mutex_unlock (&mutexsum);
    freeaddrinfo (ori_res);
  }
}

void 
dns_discovery (FILE * file, const char * domain)
{
  char line [LEN];
  char hostname [MAX];

  while (fgets (line, sizeof line, file) != NULL) {
    chomp (line);
    snprintf (hostname, sizeof hostname, "%s.%s", line, domain);
    resolve_lookup (hostname);
  }
}

void *
dns_discovery_thread (void * args)
{
  FILE * wordlist = (FILE *) args;
  dns_discovery (wordlist, dd_args.domain);
  /*pthread_exit ((void *) 0);*/
  return NULL;	
}

int
main (int argc, char ** argv) 
{
  int i;
  pthread_t * threads;
  FILE * wordlist;

  banner ();
 
  wordlist = parse_args (argc, argv);
  threads = (pthread_t *) ck_malloc (dd_args.nthreads * sizeof (pthread_t)); 
 
  for (i = 0; i < dd_args.nthreads; i++) {
    if (pthread_create (&threads[i], NULL, dns_discovery_thread, (void *)wordlist) != 0)
      error ("pthread_create");
  }
  for (i = 0; i < dd_args.nthreads; i++) {
    pthread_join (threads[i], NULL);
  }

  if (dd_args.report)
    fclose (dd_args.report);
  if (dd_args.csv)
    fclose (dd_args.csv);

  free (threads);
  fclose (wordlist);
  return 0;
}
