#ifndef INLINE_BSDSOCKET_H
#define INLINE_BSDSOCKET_H

/*
 * Inline call macros for bsdsocket.library.
 *
 * These use GCC's register-variable syntax to place arguments in the
 * correct registers per the AmiTCP bsdsocket.library FD file, then call
 * the library by LVO offset with a6=SocketBase.
 *
 * Usage: define SocketBase before including this header.
 *   struct Library *SocketBase = OpenLibrary("bsdsocket.library", 4);
 */

#include <exec/types.h>
#include <netinclude/sys/socket.h>
#include <netinclude/sys/select.h>
#include <netinclude/netinet/in.h>
#include <netinclude/netdb.h>

#define __BSDCALL(lvo, ret, regs...) \
    ({ \
        register ret _r __asm("d0"); \
        __asm volatile ("jsr " #lvo "(%%a6)" \
            : "=r"(_r) \
            : "r"((struct Library *)SocketBase), ##regs \
            : "d1","d2","d3","a0","a1","a2","cc","memory"); \
        _r; \
    })

/* LVO -30: socket(domain, type, protocol) -> d0=domain d1=type d2=protocol */
#define socket(domain, type, protocol) ({ \
    register LONG _d0 __asm("d0") = (LONG)(domain); \
    register LONG _d1 __asm("d1") = (LONG)(type); \
    register LONG _d2 __asm("d2") = (LONG)(protocol); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register LONG _r  __asm("d0"); \
    __asm volatile ("jsr -30(%%a6)" : "=r"(_r) : "r"(_d0),"r"(_d1),"r"(_d2),"r"(_a6) : "d3","a0","a1","a2","a3","cc","memory"); \
    _r; })

/* LVO -36: bind(s, name, namelen) -> d0=s a0=name d1=namelen */
#define bind(s, name, namelen) ({ \
    register LONG  _d0 __asm("d0") = (LONG)(s); \
    register APTR  _a0 __asm("a0") = (APTR)(name); \
    register LONG  _d1 __asm("d1") = (LONG)(namelen); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register LONG _r __asm("d0"); \
    __asm volatile ("jsr -36(%%a6)" : "=r"(_r) : "r"(_d0),"r"(_a0),"r"(_d1),"r"(_a6) : "d2","d3","a1","a2","a3","cc","memory"); \
    _r; })

/* LVO -42: listen(s, backlog) -> d0=s d1=backlog */
#define listen(s, backlog) ({ \
    register LONG _d0 __asm("d0") = (LONG)(s); \
    register LONG _d1 __asm("d1") = (LONG)(backlog); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register LONG _r __asm("d0"); \
    __asm volatile ("jsr -42(%%a6)" : "=r"(_r) : "r"(_d0),"r"(_d1),"r"(_a6) : "d2","d3","a0","a1","a2","a3","cc","memory"); \
    _r; })

/* LVO -48: accept(s, addr, addrlen) -> d0=s a0=addr a1=addrlen */
#define accept(s, addr, addrlen) ({ \
    register LONG _d0 __asm("d0") = (LONG)(s); \
    register APTR _a0 __asm("a0") = (APTR)(addr); \
    register APTR _a1 __asm("a1") = (APTR)(addrlen); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register LONG _r __asm("d0"); \
    __asm volatile ("jsr -48(%%a6)" : "=r"(_r) : "r"(_d0),"r"(_a0),"r"(_a1),"r"(_a6) : "d1","d2","d3","a2","a3","cc","memory"); \
    _r; })

/* LVO -54: connect(s, name, namelen) -> d0=s a0=name d1=namelen */
#define connect(s, name, namelen) ({ \
    register LONG _d0 __asm("d0") = (LONG)(s); \
    register APTR _a0 __asm("a0") = (APTR)(name); \
    register LONG _d1 __asm("d1") = (LONG)(namelen); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register LONG _r __asm("d0"); \
    __asm volatile ("jsr -54(%%a6)" : "=r"(_r) : "r"(_d0),"r"(_a0),"r"(_d1),"r"(_a6) : "d2","d3","a1","a2","a3","cc","memory"); \
    _r; })

/* LVO -60: sendto(s, msg, len, flags, to, tolen) -> d0 a0 d1 d2 a1 d3 */
#define sendto(s, msg, len, flags, to, tolen) ({ \
    register LONG _d0 __asm("d0") = (LONG)(s); \
    register APTR _a0 __asm("a0") = (APTR)(msg); \
    register LONG _d1 __asm("d1") = (LONG)(len); \
    register LONG _d2 __asm("d2") = (LONG)(flags); \
    register APTR _a1 __asm("a1") = (APTR)(to); \
    register LONG _d3 __asm("d3") = (LONG)(tolen); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register LONG _r __asm("d0"); \
    __asm volatile ("jsr -60(%%a6)" : "=r"(_r) : "r"(_d0),"r"(_a0),"r"(_d1),"r"(_d2),"r"(_a1),"r"(_d3),"r"(_a6) : "a2","a3","cc","memory"); \
    _r; })

/* LVO -66: send(s, msg, len, flags) -> d0=s a0=msg d1=len d2=flags */
#define send(s, msg, len, flags) ({ \
    register LONG _d0 __asm("d0") = (LONG)(s); \
    register APTR _a0 __asm("a0") = (APTR)(msg); \
    register LONG _d1 __asm("d1") = (LONG)(len); \
    register LONG _d2 __asm("d2") = (LONG)(flags); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register LONG _r __asm("d0"); \
    __asm volatile ("jsr -66(%%a6)" : "=r"(_r) : "r"(_d0),"r"(_a0),"r"(_d1),"r"(_d2),"r"(_a6) : "d3","a1","a2","a3","cc","memory"); \
    _r; })

/* LVO -72: recvfrom(s, buf, len, flags, from, fromlen) -> d0 a0 d1 d2 a1 a2 */
#define recvfrom(s, buf, len, flags, from, fromlen) ({ \
    register LONG _d0 __asm("d0") = (LONG)(s); \
    register APTR _a0 __asm("a0") = (APTR)(buf); \
    register LONG _d1 __asm("d1") = (LONG)(len); \
    register LONG _d2 __asm("d2") = (LONG)(flags); \
    register APTR _a1 __asm("a1") = (APTR)(from); \
    register APTR _a2 __asm("a2") = (APTR)(fromlen); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register LONG _r __asm("d0"); \
    __asm volatile ("jsr -72(%%a6)" : "=r"(_r) : "r"(_d0),"r"(_a0),"r"(_d1),"r"(_d2),"r"(_a1),"r"(_a2),"r"(_a6) : "d3","a3","cc","memory"); \
    _r; })

/* LVO -78: recv(s, buf, len, flags) -> d0=s a0=buf d1=len d2=flags */
#define recv(s, buf, len, flags) ({ \
    register LONG _d0 __asm("d0") = (LONG)(s); \
    register APTR _a0 __asm("a0") = (APTR)(buf); \
    register LONG _d1 __asm("d1") = (LONG)(len); \
    register LONG _d2 __asm("d2") = (LONG)(flags); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register LONG _r __asm("d0"); \
    __asm volatile ("jsr -78(%%a6)" : "=r"(_r) : "r"(_d0),"r"(_a0),"r"(_d1),"r"(_d2),"r"(_a6) : "d3","a1","a2","a3","cc","memory"); \
    _r; })

/* LVO -84: shutdown(s, how) -> d0=s d1=how */
#define shutdown(s, how) ({ \
    register LONG _d0 __asm("d0") = (LONG)(s); \
    register LONG _d1 __asm("d1") = (LONG)(how); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register LONG _r __asm("d0"); \
    __asm volatile ("jsr -84(%%a6)" : "=r"(_r) : "r"(_d0),"r"(_d1),"r"(_a6) : "d2","d3","a0","a1","a2","a3","cc","memory"); \
    _r; })

/* LVO -90: setsockopt(s, level, optname, optval, optlen) -> d0 d1 d2 a0 d3 */
#define setsockopt(s, level, optname, optval, optlen) ({ \
    register LONG _d0 __asm("d0") = (LONG)(s); \
    register LONG _d1 __asm("d1") = (LONG)(level); \
    register LONG _d2 __asm("d2") = (LONG)(optname); \
    register APTR _a0 __asm("a0") = (APTR)(optval); \
    register LONG _d3 __asm("d3") = (LONG)(optlen); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register LONG _r __asm("d0"); \
    __asm volatile ("jsr -90(%%a6)" : "=r"(_r) : "r"(_d0),"r"(_d1),"r"(_d2),"r"(_a0),"r"(_d3),"r"(_a6) : "a1","a2","a3","cc","memory"); \
    _r; })

/* LVO -96: getsockopt(s, level, optname, optval, optlen) -> d0 d1 d2 a0 a1 */
#define getsockopt(s, level, optname, optval, optlen) ({ \
    register LONG _d0 __asm("d0") = (LONG)(s); \
    register LONG _d1 __asm("d1") = (LONG)(level); \
    register LONG _d2 __asm("d2") = (LONG)(optname); \
    register APTR _a0 __asm("a0") = (APTR)(optval); \
    register APTR _a1 __asm("a1") = (APTR)(optlen); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register LONG _r __asm("d0"); \
    __asm volatile ("jsr -96(%%a6)" : "=r"(_r) : "r"(_d0),"r"(_d1),"r"(_d2),"r"(_a0),"r"(_a1),"r"(_a6) : "d3","a2","a3","cc","memory"); \
    _r; })

/* LVO -102: getsockname(s, name, namelen) -> d0=s a0=name a1=namelen */
#define getsockname(s, name, namelen) ({ \
    register LONG _d0 __asm("d0") = (LONG)(s); \
    register APTR _a0 __asm("a0") = (APTR)(name); \
    register APTR _a1 __asm("a1") = (APTR)(namelen); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register LONG _r __asm("d0"); \
    __asm volatile ("jsr -102(%%a6)" : "=r"(_r) : "r"(_d0),"r"(_a0),"r"(_a1),"r"(_a6) : "d1","d2","d3","a2","a3","cc","memory"); \
    _r; })

/* LVO -108: getpeername(s, name, namelen) -> d0=s a0=name a1=namelen */
#define getpeername(s, name, namelen) ({ \
    register LONG _d0 __asm("d0") = (LONG)(s); \
    register APTR _a0 __asm("a0") = (APTR)(name); \
    register APTR _a1 __asm("a1") = (APTR)(namelen); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register LONG _r __asm("d0"); \
    __asm volatile ("jsr -108(%%a6)" : "=r"(_r) : "r"(_d0),"r"(_a0),"r"(_a1),"r"(_a6) : "d1","d2","d3","a2","a3","cc","memory"); \
    _r; })

/* LVO -120: CloseSocket(s) -> d0=s */
#define CloseSocket(s) ({ \
    register LONG _d0 __asm("d0") = (LONG)(s); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register LONG _r __asm("d0"); \
    __asm volatile ("jsr -120(%%a6)" : "=r"(_r) : "r"(_d0),"r"(_a6) : "d1","d2","d3","a0","a1","a2","a3","cc","memory"); \
    _r; })

/* LVO -126: WaitSelect(nfds, readfds, writefds, exceptfds, timeout, signals)
             d0      a0        a1        a2        a3       d1 */
#define WaitSelect(nfds, rfd, wfd, efd, tv, sig) ({ \
    register LONG  _d0 __asm("d0") = (LONG)(nfds); \
    register APTR  _a0 __asm("a0") = (APTR)(rfd); \
    register APTR  _a1 __asm("a1") = (APTR)(wfd); \
    register APTR  _a2 __asm("a2") = (APTR)(efd); \
    register APTR  _a3 __asm("a3") = (APTR)(tv); \
    register ULONG _d1 __asm("d1") = (ULONG)(sig); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register LONG _r __asm("d0"); \
    __asm volatile ("jsr -126(%%a6)" : "=r"(_r) : "r"(_d0),"r"(_a0),"r"(_a1),"r"(_a2),"r"(_a3),"r"(_d1),"r"(_a6) : "d2","d3","cc","memory"); \
    _r; })

/* LVO -162: Errno() */
#define Errno() ({ \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register LONG _r __asm("d0"); \
    __asm volatile ("jsr -162(%%a6)" : "=r"(_r) : "r"(_a6) : "d1","d2","d3","a0","a1","a2","a3","cc","memory"); \
    _r; })

/* LVO -168: SetErrnoPtr(errno_ptr, size) -> a0=ptr d0=size */
#define SetErrnoPtr(ptr, size) do { \
    register APTR _a0 __asm("a0") = (APTR)(ptr); \
    register LONG _d0 __asm("d0") = (LONG)(size); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    __asm volatile ("jsr -168(%%a6)" : : "r"(_a0),"r"(_d0),"r"(_a6) : "d1","d2","d3","a1","a2","a3","cc","memory"); \
} while(0)

/* LVO -174: Inet_NtoA(in) -> d0=in */
#define Inet_NtoA(in) ({ \
    register ULONG _d0 __asm("d0") = (ULONG)(in); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register char *_r __asm("d0"); \
    __asm volatile ("jsr -174(%%a6)" : "=r"(_r) : "r"(_d0),"r"(_a6) : "d1","d2","d3","a0","a1","a2","a3","cc","memory"); \
    _r; })

/* LVO -180: inet_addr(cp) -> a0=cp */
#define inet_addr(cp) ({ \
    register APTR _a0 __asm("a0") = (APTR)(cp); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register ULONG _r __asm("d0"); \
    __asm volatile ("jsr -180(%%a6)" : "=r"(_r) : "r"(_a0),"r"(_a6) : "d1","d2","d3","a1","a2","a3","cc","memory"); \
    _r; })

/* LVO -186: Inet_LnaOf(in) -> d0=in */
#define Inet_LnaOf(in) ({ \
    register ULONG _d0 __asm("d0") = (ULONG)(in); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register ULONG _r __asm("d0"); \
    __asm volatile ("jsr -186(%%a6)" : "=r"(_r) : "r"(_d0),"r"(_a6) : "d1","d2","d3","a0","a1","a2","a3","cc","memory"); \
    _r; })

/* LVO -192: Inet_NetOf(in) -> d0=in */
#define Inet_NetOf(in) ({ \
    register ULONG _d0 __asm("d0") = (ULONG)(in); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register ULONG _r __asm("d0"); \
    __asm volatile ("jsr -192(%%a6)" : "=r"(_r) : "r"(_d0),"r"(_a6) : "d1","d2","d3","a0","a1","a2","a3","cc","memory"); \
    _r; })

/* LVO -198: Inet_MakeAddr(net, lna) -> d0=net d1=lna */
#define Inet_MakeAddr(net, lna) ({ \
    register ULONG _d0 __asm("d0") = (ULONG)(net); \
    register ULONG _d1 __asm("d1") = (ULONG)(lna); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register ULONG _r __asm("d0"); \
    __asm volatile ("jsr -198(%%a6)" : "=r"(_r) : "r"(_d0),"r"(_d1),"r"(_a6) : "d2","d3","a0","a1","a2","a3","cc","memory"); \
    _r; })

/* LVO -210: gethostbyname(name) -> a0=name */
#define gethostbyname(name) ({ \
    register APTR _a0 __asm("a0") = (APTR)(name); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register struct hostent *_r __asm("d0"); \
    __asm volatile ("jsr -210(%%a6)" : "=r"(_r) : "r"(_a0),"r"(_a6) : "d1","d2","d3","a1","a2","a3","cc","memory"); \
    _r; })

/* LVO -282: gethostname(name, namelen) -> a0=name d0=namelen */
#define gethostname(name, namelen) ({ \
    register APTR _a0 __asm("a0") = (APTR)(name); \
    register LONG _d0 __asm("d0") = (LONG)(namelen); \
    register struct Library *_a6 __asm("a6") = (struct Library *)SocketBase; \
    register LONG _r __asm("d0"); \
    __asm volatile ("jsr -282(%%a6)" : "=r"(_r) : "r"(_a0),"r"(_d0),"r"(_a6) : "d1","d2","d3","a1","a2","a3","cc","memory"); \
    _r; })

#endif /* INLINE_BSDSOCKET_H */
