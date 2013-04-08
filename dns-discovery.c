/*
DNS Discovery
  A multithreaded subdomain bruteforcer

googlecode : http://dns-discovery.googlecode.com

author	   : Victor Ramos Mello aka m0nad
emails	   : victornrm at gmail.com | m0nad at email.com
github	   : https://github.com/m0nad/

committer  : Breno Dario Cunha aka hofmann
email      : brenodario at gmail.com
github	   : https://github.com/brenocunha

copyfree   : beer license, if you like this, buy me a beer

*/
#include <string.h>
#include <getopt.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include "common.h"
#include "dns-discovery.h"

struct dns_discovery_args dd_args;
pthread_mutex_t mutexsum;

void
cleanup()
{
    if (dd_args.reg_report)
        fclose(dd_args.reg_report);
    if (dd_args.csv_report)
        fclose(dd_args.csv_report);
    if (dd_args.wildcard)
        freeaddrinfo(dd_args.wildcard);
} 

void
banner()
{
    SAY("   ___  _  ______    ___  _                              \n"
        "  / _ \\/ |/ / __/___/ _ \\(_)__ _______ _  _____ ______ __\n"
        " / // /    /\\ \\/___/ // / (_-</ __/ _ \\ |/ / -_) __/ // /\n"
        "/____/_/|_/___/   /____/_/___/\\__/\\___/___/\\__/_/  \\_, / \n"
        "                                                  /___/  \n"
        "\tby m0nad\n\n");
}

int
usage()
{
    SAY("usage: ./dns-discovery <domain> [options]\n"
        "options:\n"
        "\t-w <wordlist file> (default : " DEFAULT_WL ")\n"
        "\t-t <threads> (default : 1)\n"
        "\t-r <regular report file>\n"
        "\t-c <csv report file>\n\n");

    exit(EXIT_SUCCESS);
}

FILE *
parse_args(int argc, char ** argv)
{
    FILE * wordlist = NULL;
    char c, * ptr_wl = DEFAULT_WL; 
    if (argc < 2) 
        usage();
    dd_args.domain = argv[1];
    dd_args.nthreads = 1;
    SAY("DOMAIN: %s\n", dd_args.domain);
    argc--;
    argv++;
    opterr = 0;
    while ((c = getopt(argc, argv, "r:w:t:c:")) != -1)
        switch (c) {
            case 'w':
                ptr_wl = optarg;
                break;
            case 't':
                SAY("THREADS: %s\n", optarg);
                dd_args.nthreads = atoi(optarg);
  	        break;
            case 'r':
                SAY("REGULAR REPORT: %s\n", optarg);
                dd_args.reg_report = ck_fopen(optarg, "w");
                break;
            case 'c':
                SAY("CSV REPORT: %s\n", optarg);
                dd_args.csv_report = ck_fopen(optarg, "w");
                break;
            case '?':
                if (optopt == 'r' || optopt == 'w' || optopt == 't' || optopt == 'c') {
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
	            exit(EXIT_FAILURE);
                }
            default:
                usage();
        }

    SAY("WORDLIST: %s\n", ptr_wl);
    wordlist = ck_fopen(ptr_wl, "r");
    SAY("\n");

    return wordlist;
}

int
count_addrinfo(struct addrinfo * host)
{
    int i = 0;
    struct addrinfo * tmp1;

    for (tmp1 = host; tmp1; tmp1 = tmp1->ai_next) 
        i++;

    return i;
}

bool
compare_ai_addr(struct addrinfo * host1, struct addrinfo * host2)
{
    size_t size;

    if (host1->ai_family != host2->ai_family)
        return false;    
    
    switch (host1->ai_family) {    
        case AF_INET : size = sizeof (struct sockaddr_in) ; break;
        case AF_INET6: size = sizeof (struct sockaddr_in6); break;
    }
    
    if (memcmp(host1->ai_addr, host2->ai_addr, size) == 0)           
        return true;
    
    return false;                    
}    

bool
compare_hosts(struct addrinfo * host1, struct addrinfo * host2)
{

    bool found;
    struct addrinfo * tmp1, * tmp2;
  
    for (tmp1 = host1; tmp1; tmp1 = tmp1->ai_next) {
        found = false;
        for (tmp2 = host2; tmp2; tmp2 = tmp2->ai_next) {
            if (compare_ai_addr(tmp1,tmp2)) {
                found = true;
                break;
            }
        }
        if (!found)
            return false;
    }
    
    return true;
}

void
wildcard_detect()
{
    char rand_str[LEN], hostname[MAX];
    struct addrinfo * rand_res;
    struct addrinfo hints;

    srand(time(NULL));

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    gen_randstr(rand_str, SIZERANDSTR);
    snprintf (hostname, sizeof hostname, "%s.%s", rand_str, dd_args.domain);
    // check for host not found error pls
    if (getaddrinfo(hostname, NULL, &hints, &rand_res) == 0)
	dd_args.wildcard = rand_res;
    else dd_args.wildcard = NULL;
}

void
print_resolve_lookup(const char * hostname, struct addrinfo * res)
{
    int ipv = 0;
    void * addr_ptr = NULL;
    char addr_str[LEN];

    REG_REPORT("%s\n", hostname);
    CSV_REPORT("%s", hostname);
    for (; res; res = res->ai_next) { 
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
        inet_ntop(res->ai_family, addr_ptr, addr_str, sizeof addr_str);
        REG_REPORT("IPv%d address: %s\n", ipv, addr_str);
        CSV_REPORT(",%s", addr_str);
    }
    REG_REPORT("\n");
    CSV_REPORT("\n");
}

void
resolve_lookup(const char * hostname)
{
    struct addrinfo * res, hints;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    if (getaddrinfo(hostname, NULL, &hints, &res) == 0) {
        pthread_mutex_lock(&mutexsum);

	if (!compare_hosts(res, dd_args.wildcard))
	    print_resolve_lookup(hostname, res);

    	freeaddrinfo(res);
        pthread_mutex_unlock(&mutexsum);
    }
}

void 
dns_discovery(FILE * file, const char * domain)
{
    char line[LEN];
    char hostname[MAX];

    while (fgets(line, sizeof line, file) != NULL) {
        chomp(line);
        snprintf(hostname, sizeof hostname, "%s.%s", line, domain);
        resolve_lookup(hostname);
    }
}

void *
dns_discovery_thread(void * args)
{
    FILE * wordlist = (FILE *) args;
    dns_discovery(wordlist, dd_args.domain);
    /*pthread_exit((void *) 0);*/
    return NULL;	
}

int
main(int argc, char ** argv) 
{
    int i;
    char hostname[MAX];
    pthread_t * threads;
    FILE * wordlist;

    if (atexit(cleanup) != 0) {
        fprintf(stderr, "Cannot set exit function\n");
        return EXIT_FAILURE;
    }

    banner();
    wordlist = parse_args(argc, argv);   
    wildcard_detect();

    if (dd_args.wildcard) {
        snprintf(hostname, sizeof hostname, "*.%s", dd_args.domain);
        print_resolve_lookup(hostname, dd_args.wildcard);
    }

    threads = (pthread_t *) ck_malloc(dd_args.nthreads * sizeof(pthread_t)); 
 
    for (i = 0; i < dd_args.nthreads; i++) {
        if (pthread_create(&threads[i], NULL, dns_discovery_thread, (void *)wordlist) != 0)
            error("pthread_create");
    }
    for (i = 0; i < dd_args.nthreads; i++) {
        pthread_join(threads[i], NULL);
    }
  
    free(threads);
    fclose(wordlist);
    return EXIT_SUCCESS;
}
