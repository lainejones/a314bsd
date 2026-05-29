#ifndef A314BSD_PROTO_H
#define A314BSD_PROTO_H

#include <exec/types.h>

/* ---------------------------------------------------------------------------
 * a314bsd wire protocol v5 (2026-05-23)
 *
 * Architectural goal: each wget-visible library call (bsd_recv, bsd_send,
 * etc.) results in a SINGLE wait from wget's perspective, regardless of how
 * many A314 packets we need to move the data.  This is achieved by:
 *
 *   - One Pi-side Linux recv() per Amiga bsd_recv(): wget asks for N bytes,
 *     Pi calls socket.recv(N) once and gets up to N bytes back.
 *   - Pi streams the result back as a HEADER packet followed by zero or
 *     more raw-data packets (no per-chunk handshake from Amiga side).
 *   - The Amiga side runs a per-OpenLibrary dispatcher task that owns the
 *     A314 connection.  Library functions called by the application queue
 *     a request to that dispatcher, signal it, then Wait() ONCE on a reply
 *     signal.  The dispatcher reads all the packets, copies the data into
 *     the caller's buffer, then signals back.
 *
 * v4 problem this fixes: under v4 every bsd_recv issued N separate A314
 * round-trips (one per 245-byte chunk), with two DoIO/Wait()s per round-trip.
 * Each Wait is a preemption point where another Amiga task can leave the
 * shared FPU in an exception-set state.  When wget resumed it inherited the
 * poisoned FPU state and its bandwidth/percentage math produced NaN/Inf,
 * triggering "percentage <= 100" / "msecs >= 0" asserts.  v5 puts those
 * Wait()s in a dedicated dispatcher task instead.
 *
 * Wire framing on top of A314 PKT_DATA (each <= 252 bytes payload):
 *
 *   REQ (Amiga → Pi):
 *     hdr (6 bytes, big-endian):
 *       opcode  : 1 byte  - BSDOP_*
 *       seq     : 1 byte  - dispatcher-local sequence; Pi echoes in RES
 *       arglen  : 2 bytes - inline arg payload length (<= 240)
 *       inlen   : 2 bytes - bytes of input data following the hdr+args
 *                           (e.g. for send/sendto/setsockopt), 0 if none
 *     args[arglen]    - inline args (e.g. fd, flags, sockaddr)
 *     -- if inlen > 0, ceil(inlen / MAX_CHUNK_PAYLOAD) raw packets follow,
 *        last packet may be short.
 *
 *   RES (Pi → Amiga):
 *     hdr (11 bytes, big-endian):
 *       seq     : 1 byte  - echoed from request
 *       result  : 4 bytes - return value (signed; < 0 = -errno)
 *       errno   : 4 bytes - errno value (independent of result for ops that
 *                           return -1 but want a specific errno)
 *       outlen  : 2 bytes - bytes of output data following the hdr (e.g.
 *                           for recv/recvfrom/gethostbyname), 0 if none
 *     -- if outlen > 0, ceil(outlen / MAX_CHUNK_PAYLOAD) raw packets follow,
 *        last packet may be short.
 *
 * Stream framing rules:
 *   - REQ hdr + args MUST fit in a single PKT_DATA (so total <= 252 bytes,
 *     i.e. 6 hdr + 246 args max).  Keep arglen <= 240 to leave slack.
 *   - RES hdr is ALWAYS sent as a complete single PKT_DATA — never split.
 *   - Raw data packets carry only data bytes; no headers.  The reader counts
 *     bytes against inlen/outlen until satisfied.
 *
 * Sequence numbers are 8-bit and per-session.  Pi's response seq must match
 * the request's seq; mismatch indicates desync and the session is reset.
 * --------------------------------------------------------------------------- */

/* Maximum data payload in a single raw chunk packet.  The A314 ring buffer
 * limits PKT_DATA to 252 bytes total, and our framing doesn't add any
 * per-chunk overhead, so the full 252 is usable. */
#define BSD_MAX_CHUNK       252

/* Max inline args for a REQ.  Conservative: leaves headroom for the 6-byte
 * REQ header. */
#define BSD_MAX_REQ_ARGS    240

/* Opcodes (unchanged from v4 numbering for ease of reference). */
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

/* REQ header — 6 bytes big-endian. */
#define BSD_REQ_HDR_SIZE 6
struct BsdReqHdr {
    UBYTE opcode;
    UBYTE seq;
    UWORD arglen;
    UWORD inlen;
} __attribute__((packed));

/* RES header — 11 bytes big-endian.  Slightly larger than v4 (was 7) to
 * carry an independent errno field. */
#define BSD_RES_HDR_SIZE 11
struct BsdResHdr {
    UBYTE seq;
    LONG  result;
    LONG  errno_val;
    UWORD outlen;
} __attribute__((packed));

/* Argument encodings — payload-only, hdr+inlen handled separately.
 *
 * BSDOP_SOCKET     args: domain(2) type(2) protocol(2)
 *                  result: new amiga fd (>= 0) or -1
 *
 * BSDOP_CLOSE      args: fd(2)
 *                  result: 0 / -1
 *
 * BSDOP_CONNECT    args: fd(2) addrlen(1) addr[addrlen]
 *                  result: 0 / -1   (BLOCKS)
 *
 * BSDOP_BIND       args: fd(2) addrlen(1) addr[addrlen]
 *                  result: 0 / -1
 *
 * BSDOP_LISTEN     args: fd(2) backlog(2)
 *                  result: 0 / -1
 *
 * BSDOP_ACCEPT     args: fd(2)
 *                  result: new_fd / -1
 *                  out:    addrlen(1) addr[addrlen]
 *                  (BLOCKS)
 *
 * BSDOP_SEND       args: fd(2) flags(2)
 *                  inlen = bytes of payload to send (NO 245-byte cap)
 *                  result: bytes_sent / -1
 *
 * BSDOP_RECV       args: fd(2) flags(2) maxlen(4)
 *                  result: bytes_received (0 = EOF) / -1
 *                  outlen = bytes_received (NO 245-byte cap)
 *                  (BLOCKS until at least 1 byte or EOF/error)
 *
 * BSDOP_SENDTO     args: fd(2) flags(2) addrlen(1) addr[addrlen]
 *                  inlen = bytes of payload
 *                  result: bytes_sent / -1
 *
 * BSDOP_RECVFROM   args: fd(2) flags(2) maxlen(4)
 *                  result: bytes_received / -1
 *                  out:    addrlen(1) addr[addrlen] data[bytes_received]
 *                  (outlen = 1 + addrlen + bytes_received)
 *
 * BSDOP_SETSOCKOPT args: fd(2) level(2) optname(2) optlen(2)
 *                  inlen = optlen (the option value bytes)
 *                  result: 0 / -1
 *
 * BSDOP_GETSOCKOPT args: fd(2) level(2) optname(2) maxlen(2)
 *                  result: 0 / -1
 *                  out:    optlen(2) optval[optlen]
 *
 * BSDOP_SHUTDOWN   args: fd(2) how(2)
 *                  result: 0 / -1
 *
 * BSDOP_GETSOCKNAME args: fd(2)
 *                   result: 0 / -1
 *                   out:    addrlen(1) addr[addrlen]
 *
 * BSDOP_GETPEERNAME args: fd(2)
 *                   result: 0 / -1
 *                   out:    addrlen(1) addr[addrlen]
 *
 * BSDOP_GETHOSTBYNAME  args: namelen(1) name[namelen]
 *                      result: naddrs (>= 1) / 0 (= -1 = not found)
 *                      out:    naddrs * 4 bytes (IPv4 addrs, net order)
 *
 * BSDOP_GETHOSTBYADDR  args: addrlen(1) addr[addrlen] type(2)
 *                      result: 0 / -1
 *                      out:    hostname bytes (no NUL)
 *
 * BSDOP_INET_ADDR      args: slen(1) str[slen]
 *                      result: parsed addr (net order, as ULONG) or 0xFFFFFFFF
 *
 * BSDOP_INET_NTOA      args: addr(4)
 *                      result: 0
 *                      out:   dotted-decimal string (no NUL)
 *
 * BSDOP_GETSERVBYNAME  args: namelen(1) name[namelen] protolen(1) proto[protolen]
 *                      result: port (net order) / 0
 *                      out:    protoname bytes (no NUL)
 *
 * BSDOP_GETSERVBYPORT  args: port(2) protolen(1) proto[protolen]
 *                      result: port (net order, echoed) / 0
 *                      out:    service name bytes (no NUL)
 *
 * BSDOP_WAITSELECT     args: nfds(2) rmask(4) wmask(4) emask(4)
 *                            tv_sec(4) tv_usec(4)
 *                            tv_sec = 0xffffffff → infinite
 *                      result: count of ready fds (0 on timeout) / -1
 *                      out:    rmask(4) wmask(4) emask(4)
 *                      (BLOCKS)
 *
 * BSDOP_GETHOSTNAME    args: maxlen(2)
 *                      result: 0 / -1
 *                      out:    hostname bytes (no NUL)
 *
 * BSDOP_IOCTL          args: fd(2) request(4) arg(4)
 *                      result: 0 or value (e.g. FIONREAD returns bytes ready)
 *
 * BSDOP_SSL_CTX_NEW    args: (none)
 *                      result: ctx_id (>= 1) or -1
 *
 * BSDOP_SSL_CTX_FREE   args: ctx_id(4)
 *                      result: 0
 *
 * BSDOP_SSL_NEW        args: ctx_id(4)
 *                      result: ssl_id (>= 1) or -1
 *
 * BSDOP_SSL_FREE       args: ssl_id(4)
 *                      result: 0
 *
 * BSDOP_SSL_SET_FD     args: ssl_id(4) fd(4)
 *                      result: 0 or -1
 *
 * BSDOP_SSL_SET_SNI    args: ssl_id(4) hostlen(1) hostname[hostlen]
 *                      result: 0
 *
 * BSDOP_SSL_CONNECT    args: ssl_id(4)
 *                      result: 0 (success) or -1  (BLOCKS during handshake)
 *
 * BSDOP_SSL_SHUTDOWN   args: ssl_id(4)
 *                      result: 0 or -1
 *
 * BSDOP_SSL_READ       args: ssl_id(4) maxlen(4)
 *                      result: bytes_read / 0 (EOF) / -1  (BLOCKS)
 *                      out:    data[bytes_read]
 *
 * BSDOP_SSL_WRITE      args: ssl_id(4)
 *                      inlen = len (plaintext bytes to encrypt and send)
 *                      result: bytes_written or -1
 *
 * BSDOP_SSL_GET_ERROR  args: ssl_id(4) ret(4)
 *                      result: SSL error code (0=NONE 6=ZERO_RETURN 5=SYSCALL)
 *                      Note: implemented locally on the Amiga — no Pi round-trip.
 */

#endif /* A314BSD_PROTO_H */
