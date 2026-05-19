#ifndef NETINET_IN_H
#define NETINET_IN_H

#include <exec/types.h>

struct in_addr {
    ULONG s_addr;   /* address in network byte order */
};

struct sockaddr_in {
    UWORD          sin_family;   /* AF_INET */
    UWORD          sin_port;     /* port, network byte order */
    struct in_addr sin_addr;     /* IP address, network byte order */
    BYTE           sin_zero[8];  /* padding */
};

/* IP protocols */
#define IPPROTO_IP      0
#define IPPROTO_ICMP    1
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17
#define IPPROTO_RAW     255

/* IP-level socket options */
#define IP_OPTIONS          1
#define IP_TOS              3
#define IP_TTL              4
#define IP_MULTICAST_IF     9
#define IP_MULTICAST_TTL    10
#define IP_MULTICAST_LOOP   11
#define IP_ADD_MEMBERSHIP   12
#define IP_DROP_MEMBERSHIP  13

/* Well-known addresses */
#define INADDR_ANY          0x00000000UL
#define INADDR_LOOPBACK     0x7f000001UL
#define INADDR_BROADCAST    0xffffffffUL
#define INADDR_NONE         0xffffffffUL

/*
 * Amiga 68k is big-endian, which is also network byte order.
 * These macros are no-ops but must exist for portable code.
 */
#define htons(x)    ((UWORD)(x))
#define ntohs(x)    ((UWORD)(x))
#define htonl(x)    ((ULONG)(x))
#define ntohl(x)    ((ULONG)(x))

#endif /* NETINET_IN_H */
