#ifndef A314BSD_PROTO_H
#define A314BSD_PROTO_H

#include <exec/types.h>

/* Opcodes */
#define BSDOP_SOCKET        1
#define BSDOP_CLOSE         2
#define BSDOP_CONNECT       3
#define BSDOP_BIND          4
#define BSDOP_LISTEN        5
#define BSDOP_ACCEPT        6
#define BSDOP_SEND          7
#define BSDOP_RECV          8
#define BSDOP_SENDTO        9
#define BSDOP_RECVFROM      10
#define BSDOP_SETSOCKOPT    11
#define BSDOP_GETSOCKOPT    12
#define BSDOP_SHUTDOWN      13
#define BSDOP_GETSOCKNAME   14
#define BSDOP_GETPEERNAME   15
#define BSDOP_GETHOSTBYNAME 16
#define BSDOP_GETHOSTBYADDR 17
#define BSDOP_INET_ADDR     18
#define BSDOP_INET_NTOA     19
#define BSDOP_GETSERVBYNAME 20
#define BSDOP_GETSERVBYPORT 21
#define BSDOP_WAITSELECT    22
#define BSDOP_GETHOSTNAME   23
#define BSDOP_IOCTL         24

/*
 * Request header — 4 bytes, big-endian
 *   opcode  : BSDOP_* above
 *   seq     : rolling counter; Pi echoes it in the response
 *   arglen  : byte count of argument payload following this header
 */
#define BSD_REQ_HDR_SIZE 4
struct BsdReqHdr {
    UBYTE opcode;
    UBYTE seq;
    UWORD arglen;
} __attribute__((packed));

/*
 * Response header — 7 bytes, big-endian
 *   seq     : echoed from request
 *   result  : >= 0 success (return value), < 0 = -errno (BSD/AmiTCP values)
 *   datalen : byte count of optional payload following this header
 */
#define BSD_RSP_HDR_SIZE 7
struct BsdRspHdr {
    UBYTE seq;
    LONG  result;
    UWORD datalen;
} __attribute__((packed));

/*
 * Argument encodings — all fields big-endian unless noted:
 *
 * BSDOP_SOCKET     domain(2) type(2) protocol(2)
 *   -> result = new amiga fd (>= 1)
 *
 * BSDOP_CLOSE      fd(2)
 *   -> result = 0
 *
 * BSDOP_CONNECT    fd(2) addrlen(1) addr[addrlen]
 *   -> result = 0  (BLOCKS until connected or error)
 *
 * BSDOP_BIND       fd(2) addrlen(1) addr[addrlen]
 *   -> result = 0
 *
 * BSDOP_LISTEN     fd(2) backlog(2)
 *   -> result = 0
 *
 * BSDOP_ACCEPT     fd(2)
 *   -> result = new_fd, data = addrlen(1) addr[addrlen]  (BLOCKS)
 *
 * BSDOP_SEND       fd(2) flags(2) datalen(2) data[datalen]
 *   -> result = bytes_sent
 *   NOTE: datalen must be ≤ 242 (A314 ring-buffer limit: 252 − 10 fixed bytes)
 *
 * BSDOP_RECV       fd(2) flags(2) maxlen(2)
 *   -> result = bytes_received, data = received bytes  (BLOCKS)
 *   NOTE: maxlen must be ≤ 245 (A314 ring-buffer limit: 252 − 7 RSP header)
 *
 * BSDOP_SENDTO     fd(2) flags(2) addrlen(1) addr[addrlen] datalen(2) data[datalen]
 *   -> result = bytes_sent
 *
 * BSDOP_RECVFROM   fd(2) flags(2) maxlen(2)
 *   -> result = bytes_received, data = bytes + addrlen(1) + addr[addrlen]  (BLOCKS)
 *
 * BSDOP_SETSOCKOPT fd(2) level(2) optname(2) optlen(2) optval[optlen]
 *   -> result = 0
 *
 * BSDOP_GETSOCKOPT fd(2) level(2) optname(2)
 *   -> result = 0, data = optlen(2) optval[optlen]
 *
 * BSDOP_SHUTDOWN   fd(2) how(2)
 *   -> result = 0
 *
 * BSDOP_GETSOCKNAME  fd(2)
 *   -> result = 0, data = addrlen(1) addr[addrlen]
 *
 * BSDOP_GETPEERNAME  fd(2)
 *   -> result = 0, data = addrlen(1) addr[addrlen]
 *
 * BSDOP_GETHOSTBYNAME  namelen(1) name[namelen]
 *   -> result = naddrs (>= 1), data = naddrs*4 bytes (IPv4 addrs, net order)
 *
 * BSDOP_GETHOSTBYADDR  addrlen(1) addr[addrlen] type(2)
 *   -> result = 0, data = namelen(1) name[namelen]
 *
 * BSDOP_INET_ADDR      slen(1) str[slen]
 *   -> result = 0, data = 4 bytes (address, net order)
 *   -> result = -1 on parse error
 *
 * BSDOP_INET_NTOA      addr(4)  (net order)
 *   -> result = 0, data = string bytes (no NUL)
 *
 * BSDOP_GETSERVBYNAME  namelen(1) name[namelen] protolen(1) proto[protolen]
 *   -> result = port (host order), data = protoname bytes (no NUL)
 *
 * BSDOP_GETSERVBYPORT  port(2) protolen(1) proto[protolen]
 *   -> result = port (host order), data = service name bytes (no NUL)
 *
 * BSDOP_WAITSELECT     nfds(2) readmask(4) writemask(4) exceptmask(4)
 *                      tv_sec(4) tv_usec(4)
 *                      tv_sec = 0xffffffff means infinite timeout
 *   -> result = count of ready fds, data = readmask(4) writemask(4) exceptmask(4)
 *   (BLOCKS until at least one fd ready or timeout)
 *
 * BSDOP_GETHOSTNAME    maxlen(2)
 *   -> result = 0, data = hostname bytes (no NUL)
 *
 * BSDOP_IOCTL          fd(2) request(4) arg(4)
 *   -> result = 0 or value (e.g. FIONREAD returns byte count)
 *   For FIONBIO: arg = 0 to clear non-blocking, 1 to set
 */

#endif /* A314BSD_PROTO_H */
