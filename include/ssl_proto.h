#ifndef A314SSL_PROTO_H
#define A314SSL_PROTO_H

#include <exec/types.h>

/* ---------------------------------------------------------------------------
 * a314ssl wire protocol
 *
 * SSL opcodes ride the SAME A314 stream as bsdsocket (service "bsdsocket").
 * The bsdsocket.py dispatch loop handles opcodes 50+ as SSL operations.
 * They use the same REQ/RES framing defined in bsd_proto.h.
 *
 * WHY same stream: bsdsocket.py owns the fd → Linux socket mapping for the
 * session.  SSL_set_fd passes an fd number; the Pi looks it up in
 * sess.sockets[fd] and wraps it in ssl.SSLContext.wrap_socket().  A separate
 * stream would have a different fd namespace and couldn't find the socket.
 *
 * HOW amissl.library calls these: amissl.library opens bsdsocket.library on
 * its own Open, stores BsdBase, and calls new SSL LVOs on bsdsocket.library
 * (see ssl_lvo.h).  Those LVO stubs in bsdsocket.library's function table
 * run the same do_rpc machinery with BSDOP_SSL_* opcodes.
 *
 * SSL object IDs: Pi allocates monotonic ULONG IDs for SSL_CTX and SSL
 * objects, stored in the Session.  ID 0 is always invalid (= failure/NULL).
 *
 * Arg encodings (all multi-byte fields big-endian, matching bsd_proto.h):
 *
 *   BSDOP_SSL_CTX_NEW   args: (none)
 *                       result: ctx_id (ULONG > 0) or 0 = failure
 *
 *   BSDOP_SSL_CTX_FREE  args: ctx_id(4)
 *                       result: 0
 *
 *   BSDOP_SSL_NEW       args: ctx_id(4)
 *                       result: ssl_id (ULONG > 0) or 0 = failure
 *
 *   BSDOP_SSL_FREE      args: ssl_id(4)
 *                       result: 0
 *
 *   BSDOP_SSL_SET_FD    args: ssl_id(4) fd(2)
 *                       result: 0 / -1
 *                       Associates ssl_id with bsdsocket session fd.
 *                       Pi stores fd; wraps the socket on SSL_connect.
 *
 *   BSDOP_SSL_SET_SNI   args: ssl_id(4) namelen(1) name[namelen]
 *                       result: 0 / -1
 *                       Stores SNI hostname for use during SSL_connect
 *                       handshake.  Call before SSL_connect.
 *
 *   BSDOP_SSL_CONNECT   args: ssl_id(4)
 *                       result: 0 (success) / -1 (error)
 *                       BLOCKS — Pi does full TLS handshake using Python ssl
 *                       module.  Pi uses system CA bundle (apt-managed, always
 *                       current) — this is the key advantage over AmiSSL.
 *
 *   BSDOP_SSL_SHUTDOWN  args: ssl_id(4)
 *                       result: 0 / -1
 *
 *   BSDOP_SSL_READ      args: ssl_id(4) maxlen(4)
 *                       result: bytes_read (> 0) / 0 (EOF/clean shutdown) / -1
 *                       out:    data bytes (outlen = result when result > 0)
 *                       BLOCKS until data available, EOF, or error.
 *
 *   BSDOP_SSL_WRITE     args: ssl_id(4)
 *                       inlen:  payload bytes
 *                       result: bytes_written / -1
 *
 *   BSDOP_SSL_GET_ERROR args: ssl_id(4) ret(4 signed)
 *                       result: SSL_ERROR_* constant matching OpenSSL values
 * --------------------------------------------------------------------------- */

#define BSDOP_SSL_CTX_NEW    50
#define BSDOP_SSL_CTX_FREE   51
#define BSDOP_SSL_NEW        52
#define BSDOP_SSL_FREE       53
#define BSDOP_SSL_SET_FD     54
#define BSDOP_SSL_SET_SNI    55
#define BSDOP_SSL_CONNECT    56
#define BSDOP_SSL_SHUTDOWN   57
#define BSDOP_SSL_READ       58
#define BSDOP_SSL_WRITE      59
#define BSDOP_SSL_GET_ERROR  60

/* SSL_get_error return codes — match OpenSSL values exactly */
#define SSL_ERROR_NONE              0
#define SSL_ERROR_SSL               1
#define SSL_ERROR_WANT_READ         2
#define SSL_ERROR_WANT_WRITE        3
#define SSL_ERROR_WANT_X509_LOOKUP  4
#define SSL_ERROR_SYSCALL           5
#define SSL_ERROR_ZERO_RETURN       6
#define SSL_ERROR_WANT_CONNECT      7
#define SSL_ERROR_WANT_ACCEPT       8

#endif /* A314SSL_PROTO_H */
