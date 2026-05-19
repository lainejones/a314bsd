#ifndef SYS_SELECT_H
#define SYS_SELECT_H

#include <exec/types.h>

/*
 * AmiTCP uses a single 32-bit word as fd_set.
 * Bit N is set when socket fd N is in the set.
 * Maximum 32 simultaneous sockets per task.
 */
typedef ULONG fd_set;

#define FD_SETSIZE  32

#define FD_SET(n, p)    (*(p) |=  (1UL << (n)))
#define FD_CLR(n, p)    (*(p) &= ~(1UL << (n)))
#define FD_ISSET(n, p)  (((*(p)) >> (n)) & 1UL)
#define FD_ZERO(p)      (*(p) = 0UL)

#ifndef _TIMEVAL_DEFINED
#define _TIMEVAL_DEFINED
struct timeval {
    LONG tv_sec;    /* seconds */
    LONG tv_usec;   /* microseconds */
};
#endif

#endif /* SYS_SELECT_H */
