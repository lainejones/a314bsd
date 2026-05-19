#ifndef SYS_SOCKET_H
#define SYS_SOCKET_H

#include <exec/types.h>

/* Socket types */
#define SOCK_STREAM     1
#define SOCK_DGRAM      2
#define SOCK_RAW        3
#define SOCK_RDM        4
#define SOCK_SEQPACKET  5

/* Address families */
#define AF_UNSPEC       0
#define AF_INET         2

/* Protocol families */
#define PF_UNSPEC       AF_UNSPEC
#define PF_INET         AF_INET

/* Message flags */
#define MSG_OOB         0x0001
#define MSG_PEEK        0x0002
#define MSG_DONTROUTE   0x0004
#define MSG_EOR         0x0008
#define MSG_TRUNC       0x0010
#define MSG_CTRUNC      0x0020
#define MSG_WAITALL     0x0040
#define MSG_DONTWAIT    0x0080

/* Socket-level options (SOL_SOCKET) */
#define SOL_SOCKET      0xffff

#define SO_DEBUG        0x0001
#define SO_ACCEPTCONN   0x0002
#define SO_REUSEADDR    0x0004
#define SO_KEEPALIVE    0x0008
#define SO_DONTROUTE    0x0010
#define SO_BROADCAST    0x0020
#define SO_USELOOPBACK  0x0040
#define SO_LINGER       0x0080
#define SO_OOBINLINE    0x0100
#define SO_SNDBUF       0x1001
#define SO_RCVBUF       0x1002
#define SO_SNDLOWAT     0x1003
#define SO_RCVLOWAT     0x1004
#define SO_SNDTIMEO     0x1005
#define SO_RCVTIMEO     0x1006
#define SO_ERROR        0x1007
#define SO_TYPE         0x1008

/* shutdown() how */
#define SHUT_RD         0
#define SHUT_WR         1
#define SHUT_RDWR       2

/* IoctlSocket() requests */
#define FIONREAD        0x4004667fl
#define FIONBIO         0x8004667el
#define FIOASYNC        0x8004667dl
#define SIOCATMARK      0x4004667bl

struct sockaddr {
    UWORD sa_family;
    BYTE  sa_data[14];
};

struct linger {
    LONG l_onoff;
    LONG l_linger;
};

#endif /* SYS_SOCKET_H */
