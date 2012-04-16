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
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <netdb.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#define SAMPLE_SIZE 10
#define LEN 256
#define MAX 512
#define DEFAULT_WL "wordlist.wl"

#define SAY(args...)\
  fprintf (stdout, args);

#define REG_REPORT(args...)\
  SAY (args);\
  if (dd_args.reg_report)\
    fprintf (dd_args.reg_report, args);

#define CSV_REPORT(args...)\
  if (dd_args.csv_report)\
    fprintf (dd_args.csv_report, args);

struct dns_discovery_args {
  FILE * reg_report;
  FILE * csv_report;
  char * domain;
  int nthreads;
};
struct dns_discovery_args dd_args;
pthread_mutex_t mutexsum;

void
error (const char * msg)
{
  perror (msg);
  exit (EXIT_FAILURE);
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
cleanup ()
{
  if (dd_args.reg_report)
    fclose (dd_args.reg_report);
  if (dd_args.csv_report)
    fclose (dd_args.csv_report);
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
       "\t-r <regular report file>\n"
       "\t-c <csv report file>\n\n", DEFAULT_WL);

  exit (EXIT_SUCCESS);
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
  SAY ("DOMAIN: %s\n", dd_args.domain);
  argc--;
  argv++;
  opterr = 0;
  while ((c = getopt (argc, argv, "r:w:t:c:")) != -1)
    switch (c) {
      case 'w':
        ptr_wl = optarg;
        break;
      case 't':
        SAY ("THREADS: %s\n", optarg);
        dd_args.nthreads = atoi (optarg);
  	break;
      case 'r':
        SAY ("REGULAR REPORT: %s\n", optarg);
        dd_args.reg_report = ck_fopen (optarg, "w");
        break;
      case 'c':
        SAY ("CSV REPORT: %s\n", optarg);
        dd_args.csv_report = ck_fopen (optarg, "w");
        break;
      case '?':
        if (optopt == 'r' || optopt == 'w' || optopt == 't' || optopt == 'c') {
          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
	  exit (EXIT_FAILURE);
        }
      default:
        usage ();
    }
  SAY ("WORDLIST: %s\n", ptr_wl);
  wordlist = ck_fopen (ptr_wl, "r");
  SAY ("\n");

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
    REG_REPORT ("%s\n", hostname);
    CSV_REPORT ("%s", hostname);
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
      REG_REPORT ("IPv%d address: %s\n", ipv, addr_str);
      CSV_REPORT (",%s", addr_str);
    }
    REG_REPORT ("\n");
    CSV_REPORT ("\n");
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

void
gen_randstr(char * str_rand, const int len)
{
   int i;
   static const char alphanum [] =
      "0123456789"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz";


   for (i = 0; i < len; i++) {
       srand(time(NULL) + i);
       str_rand[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
   }

   str_rand[len] = 0;
   scanf("%s", str_rand);
}

int count_addrinfo(struct addrinfo * host)
{
    int i = 0;
    struct addrinfo * tmp1;

    for (tmp1 = host ; tmp1 ; tmp1 = tmp1->ai_next) 
        i++;

    return i;
}
bool compare_ai_addr(struct addrinfo * host1, struct addrinfo * host2){

    size_t size;

    if (host1->ai_family != host2->ai_family)
        return false;    
    
    switch (host1->ai_family){    
        case AF_INET : size = sizeof (struct sockaddr_in) ; break;
        case AF_INET6: size = sizeof (struct sockaddr_in6); break;
    }
    
    if (memcmp(host1->ai_addr, host2->ai_addr, size) == 0)           
        return true;
    
    return false;                    
}    

struct hash_addrinfo {
    struct addrinfo * host;
    int sum;
};

bool compare_hosts(struct addrinfo * host1, struct addrinfo * host2){
    int size;
    bool found;
    struct addrinfo * tmp1, * tmp2;

    size = count_addrinfo(host1);
    if (size != count_addrinfo(host2))
        return false;
    
    for (tmp1 = host1 ; tmp1 ; tmp1 = tmp1->ai_next) {
        found = false;
        for (tmp2 = host2 ; tmp2 ; tmp2 = tmp2->ai_next){
            if (compare_ai_addr(tmp1,tmp2)){
                found = true;
                break;
            }
        }
        if (!found)
            return false;
    }
    
    return true;
}

float
compare_samples(struct addrinfo ** rand_res, int n_res)
{
    int i,j, top = 0, max = 0; //sum = 0,
    bool found;
    float similarity;
    struct hash_addrinfo * hash_acc = (struct hash_addrinfo *) ck_malloc(n_res * sizeof(struct hash_addrinfo));


    for (i = 0 ; i < n_res ; i++) {
       hash_acc[i].host = NULL;
       hash_acc[i].sum = 0;
    }

    hash_acc[top].host = rand_res[top];
    hash_acc[top].sum = 1;

    for (i = 1 ; i < n_res ; i++) {
        found = false;
        for (j = 0 ; j < n_res ; j++){
            if (hash_acc[j].host != NULL && compare_hosts(rand_res[i], hash_acc[j].host)) {
                hash_acc[j].sum++;
                found = true;
		break;
            } 
        }
        if (!found) {
    	    hash_acc[++top].host = rand_res[j];
	    hash_acc[top].sum = 1;
        }
    }

    for (i = 0 ; i < n_res ; i++) {
	if (hash_acc[i].sum > max)
	    max = hash_acc[i].sum;
    }
    printf ("max %d\n", max);
    similarity = (max * 100) / n_res;

    return similarity;
}


float
wildcard_prob(char * domain,  const int n_samples)
{
    int i, err = 0;
    float similarity;
    char rand_str[LEN], hostname[MAX];
    struct addrinfo ** rand_res;
    struct addrinfo hints;
    
    rand_res = (struct addrinfo **) ck_malloc(n_samples * sizeof(struct addrinfo *));
    
    memset (&hints, 0, sizeof hints);
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;
    
    for (i = 0 ; i < n_samples ; i++) {
        gen_randstr(rand_str, SAMPLE_SIZE);
        snprintf (hostname, sizeof hostname, "%s.%s", rand_str, domain);
	printf("host: %s\n", hostname);
        // check for host not found error pls
        if (getaddrinfo (hostname, NULL, &hints, &rand_res[i]) != 0) {
            err = -1;
            goto err;
        }   
    }  
    
    similarity = compare_samples(rand_res, n_samples);
    
err:
    free(rand_res);
    
    //if (err < 0)
    //   return err;
    
    return similarity;
}

int
main (int argc, char ** argv) 
{
  int i;
  pthread_t * threads;
  FILE * wordlist;

  if (atexit (cleanup) != 0) {
    fprintf (stderr, "Cannot set exit function\n");
    return EXIT_FAILURE;
  }

  banner ();
 

  wordlist = parse_args (argc, argv);

  printf ("similarity: %f\n", wildcard_prob(dd_args.domain, 5));
  threads = (pthread_t *) ck_malloc (dd_args.nthreads * sizeof (pthread_t)); 
 
  for (i = 0; i < dd_args.nthreads; i++) {
    if (pthread_create (&threads[i], NULL, dns_discovery_thread, (void *)wordlist) != 0)
      error ("pthread_create");
  }
  for (i = 0; i < dd_args.nthreads; i++) {
    pthread_join (threads[i], NULL);
  }
  
  free (threads);
  fclose (wordlist);

  return EXIT_SUCCESS;
}
