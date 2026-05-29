#ifndef SSL_LVO_H
#define SSL_LVO_H

/* ---------------------------------------------------------------------------
 * New bsdsocket.library LVOs for SSL operations.
 *
 * These extend bsdsocket.library's function table past the current
 * LIB_NEGSIZE_VAL of 822.  amissl.library calls these via JSR lvo(a6)
 * with a6 = BsdBase, which it opens on its own Open call.
 *
 * To activate these in a314bsd:
 *
 *   1. a314bsd/amiga/lib_start.S:
 *      - Change LIB_NEGSIZE_VAL from 822 to 888
 *      - Append 11 new .long entries before the terminal -1 (after -822 stubs)
 *      - Add 11 new .extern _bsd_ssl_* declarations
 *
 *   2. a314bsd/amiga/bsdsocket.c (or a new ssl_stubs.c linked in):
 *      - Implement the 11 ssl_* functions using do_rpc with BSDOP_SSL_* opcodes
 *      - Calling convention: a6 = BsdBase (find_session via base)
 *      - See below for per-function register args
 *
 *   3. a314bsd/pi/bsdsocket.py:
 *      - Merge pi/ssl_addon.py into the dispatch_op handler
 *      - Add SSL state fields to Session.__init__
 *
 * Calling convention for each SSL LVO (a6 = BsdBase in all cases):
 *
 *   bsd_ssl_ctx_new   ()                          d0 = ctx_id or 0
 *   bsd_ssl_ctx_free  (d0 = ctx_id)               d0 = 0
 *   bsd_ssl_new       (d0 = ctx_id)               d0 = ssl_id or 0
 *   bsd_ssl_free      (d0 = ssl_id)               d0 = 0
 *   bsd_ssl_set_fd    (d0 = ssl_id, d1 = fd)      d0 = 0/-1
 *   bsd_ssl_set_sni   (d0 = ssl_id, a0 = name)    d0 = 0/-1
 *   bsd_ssl_connect   (d0 = ssl_id)               d0 = 0/-1  (BLOCKS)
 *   bsd_ssl_shutdown  (d0 = ssl_id)               d0 = 0/-1
 *   bsd_ssl_read      (d0 = ssl_id, a0 = buf,
 *                      d1 = maxlen)               d0 = bytes/0/-1 (BLOCKS)
 *   bsd_ssl_write     (d0 = ssl_id, a0 = buf,
 *                      d1 = len)                  d0 = bytes/-1
 *   bsd_ssl_get_error (d0 = ssl_id, d1 = ret)     d0 = SSL_ERROR_*
 * --------------------------------------------------------------------------- */

#define BSDSSL_LVO_CTX_NEW      (-828)
#define BSDSSL_LVO_CTX_FREE     (-834)
#define BSDSSL_LVO_NEW          (-840)
#define BSDSSL_LVO_FREE         (-846)
#define BSDSSL_LVO_SET_FD       (-852)
#define BSDSSL_LVO_SET_SNI      (-858)
#define BSDSSL_LVO_CONNECT      (-864)
#define BSDSSL_LVO_SHUTDOWN     (-870)
#define BSDSSL_LVO_READ         (-876)
#define BSDSSL_LVO_WRITE        (-882)
#define BSDSSL_LVO_GET_ERROR    (-888)

/* New LIB_NEGSIZE_VAL for bsdsocket.library after SSL extension */
#define BSDSSL_NEW_NEGSIZE      888

#endif /* SSL_LVO_H */
