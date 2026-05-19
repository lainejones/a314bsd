#ifndef ARPA_INET_H
#define ARPA_INET_H

#include <exec/types.h>
#include <netinclude/netinet/in.h>

/*
 * These are declared here for documentation; the actual implementations
 * live in bsdsocket.library and are called via the LVO jump table.
 * Include <inline/bsdsocket.h> or <proto/bsdsocket.h> for call macros.
 */

/* Convert dotted-decimal string to network-order 32-bit address.
   Returns INADDR_NONE on error. */
/* ULONG inet_addr(const char *cp); */

/* Convert network-order address to dotted-decimal string (static buffer). */
/* char *Inet_NtoA(ULONG in); */

/* Classful address decomposition (rarely needed for modern code) */
/* ULONG Inet_LnaOf(ULONG in);   -- local network address part */
/* ULONG Inet_NetOf(ULONG in);   -- network number part */
/* ULONG Inet_MakeAddr(ULONG net, ULONG lna); -- combine net+lna */

#endif /* ARPA_INET_H */
