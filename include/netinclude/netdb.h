#ifndef NETDB_H
#define NETDB_H

struct hostent {
    char  *h_name;        /* official name of host */
    char **h_aliases;     /* NULL-terminated alias list */
    int    h_addrtype;    /* host address type (AF_INET) */
    int    h_length;      /* length of address in bytes */
    char **h_addr_list;   /* NULL-terminated list of addresses */
};
#define h_addr  h_addr_list[0]  /* first address, for compatibility */

struct servent {
    char  *s_name;        /* official service name */
    char **s_aliases;     /* alias list */
    int    s_port;        /* port number, network byte order */
    char  *s_proto;       /* protocol to use */
};

struct protoent {
    char  *p_name;        /* official protocol name */
    char **p_aliases;     /* alias list */
    int    p_proto;       /* protocol number */
};

/* h_errno values returned from gethostbyname/gethostbyaddr */
#define HOST_NOT_FOUND  1   /* authoritative answer: host not found */
#define TRY_AGAIN       2   /* non-authoritative, try again */
#define NO_RECOVERY     3   /* non-recoverable error */
#define NO_DATA         4   /* valid name, no record of requested type */
#define NO_ADDRESS      NO_DATA

#endif /* NETDB_H */
