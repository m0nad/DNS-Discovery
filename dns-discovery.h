#define LEN 256
#define MAX 512
#define DEFAULT_WL "wordlist.wl"
#define SAMPLE_SIZE 10

#define SAY(args...)\
    fprintf(stdout, args);

#define REG_REPORT(args...)\
    SAY(args);\
    if (dd_args.reg_report)\
        fprintf(dd_args.reg_report, args);

#define CSV_REPORT(args...)\
    if (dd_args.csv_report)\
        fprintf(dd_args.csv_report, args);

struct dns_discovery_args {
    FILE * reg_report;
    FILE * csv_report;
    char * domain;
    int nthreads;
};

struct hash_addrinfo {
    struct addrinfo * host;
    int count;
};
