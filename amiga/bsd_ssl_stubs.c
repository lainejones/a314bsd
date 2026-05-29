/*
 * bsd_ssl_stubs.c — bsdsocket.library SSL extension (LVOs -828 to -888)
 *
 * Implements 11 new bsdsocket LVOs that proxy SSL operations to the Pi via
 * BSDOP_SSL_* opcodes (50–60) over the existing A314 bsdsocket stream.
 *
 * DO NOT compile this file directly.  It is #included from bsdsocket_main.c,
 * which gives it access to bsdsocket.c's static helpers:
 *   find_session()   — looks up the BsdSession for the calling Amiga task
 *   do_rpc()         — PutMsg / WaitPort / GetMsg to the dispatcher task
 *   w16(p, v)        — write big-endian UWORD into args[]
 *   w32(p, v)        — write big-endian ULONG into args[]
 *
 * Calling convention (set by lib_start.S FuncTable entries):
 *   All functions receive a6 = BsdBase (bsdsocket.library base pointer).
 *   Per-function register args are listed in each function header.
 *
 * Wire format — matches _ssl_dispatch() in pi/bsdsocket.py:
 *   BSDOP_SSL_CTX_NEW    args: (none)
 *   BSDOP_SSL_CTX_FREE   args: ctx_id(4)
 *   BSDOP_SSL_NEW        args: ctx_id(4)
 *   BSDOP_SSL_FREE       args: ssl_id(4)
 *   BSDOP_SSL_SET_FD     args: ssl_id(4) fd(2)
 *   BSDOP_SSL_SET_SNI    args: ssl_id(4) nlen(1) name[nlen]
 *   BSDOP_SSL_CONNECT    args: ssl_id(4)
 *   BSDOP_SSL_SHUTDOWN   args: ssl_id(4)
 *   BSDOP_SSL_READ       args: ssl_id(4) maxlen(4)   out: data[result]
 *   BSDOP_SSL_WRITE      args: ssl_id(4)             in:  data[len]
 *   BSDOP_SSL_GET_ERROR  args: ssl_id(4) ret(4)
 *
 * All IDs (ctx_id, ssl_id) are opaque ULONGs allocated by the Pi.
 * ID 0 is always invalid (= NULL).
 *
 * Build 13 note: all functions use find_session() + do_rpc() — the same path
 * that bsd_gethostbyname uses and that provably works (session 3 in Pi log).
 * The previous find_ssl_session() + do_ssl_rpc() cross-task machinery was
 * removed after Build 12 probes confirmed it sends zero Pi ops.
 */

#include "ssl_proto.h"   /* BSDOP_SSL_* = 50–60 */

/* ---- bsd_ssl_ctx_new (LVO -828) ------------------------------------------
 * Create a new TLS client context on the Pi.
 * a6 = BsdBase
 * Returns: ctx_id (> 0) on success, 0 on failure.
 */
ULONG bsd_ssl_ctx_new(struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    if (!sess) return 0;
    sess->req.opcode  = BSDOP_SSL_CTX_NEW;
    sess->req.arglen  = 0;
    sess->req.indata  = NULL;  sess->req.inlen  = 0;
    sess->req.outdata = NULL;  sess->req.outmax = 0;
    do_rpc(sess);
    return (ULONG)sess->req.result;   /* ctx_id or 0 */
}

/* ---- bsd_ssl_ctx_free (LVO -834) -----------------------------------------
 * Release a context on the Pi.
 * d0 = ctx_id, a6 = BsdBase
 */
void bsd_ssl_ctx_free(ULONG ctx_id __asm("d0"), struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    if (!sess || !ctx_id) return;
    sess->req.opcode  = BSDOP_SSL_CTX_FREE;
    sess->req.arglen  = 4;
    w32(&sess->req.args[0], ctx_id);
    sess->req.indata  = NULL;  sess->req.inlen  = 0;
    sess->req.outdata = NULL;  sess->req.outmax = 0;
    do_rpc(sess);
}

/* ---- bsd_ssl_new (LVO -840) -----------------------------------------------
 * Create a new SSL object under the given context.
 * d0 = ctx_id, a6 = BsdBase
 * Returns: ssl_id (> 0) on success, 0 on failure.
 */
ULONG bsd_ssl_new(ULONG ctx_id __asm("d0"), struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    if (!sess || !ctx_id) return 0;
    sess->req.opcode  = BSDOP_SSL_NEW;
    sess->req.arglen  = 4;
    w32(&sess->req.args[0], ctx_id);
    sess->req.indata  = NULL;  sess->req.inlen  = 0;
    sess->req.outdata = NULL;  sess->req.outmax = 0;
    do_rpc(sess);
    return (ULONG)sess->req.result;   /* ssl_id or 0 */
}

/* ---- bsd_ssl_free (LVO -846) ----------------------------------------------
 * Release an SSL object on the Pi.
 * d0 = ssl_id, a6 = BsdBase
 */
void bsd_ssl_free(ULONG ssl_id __asm("d0"), struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    if (!sess || !ssl_id) return;
    sess->req.opcode  = BSDOP_SSL_FREE;
    sess->req.arglen  = 4;
    w32(&sess->req.args[0], ssl_id);
    sess->req.indata  = NULL;  sess->req.inlen  = 0;
    sess->req.outdata = NULL;  sess->req.outmax = 0;
    do_rpc(sess);
}

/* ---- bsd_ssl_set_fd (LVO -852) --------------------------------------------
 * Associate an SSL object with a bsdsocket fd.
 * d0 = ssl_id, d1 = fd, a6 = BsdBase
 * Returns: 0 on success, -1 on error.
 */
LONG bsd_ssl_set_fd(ULONG ssl_id __asm("d0"), LONG fd __asm("d1"),
                    struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    if (!sess || !ssl_id) return -1;
    sess->req.opcode  = BSDOP_SSL_SET_FD;
    sess->req.arglen  = 6;                   /* ssl_id(4) fd(2) */
    w32(&sess->req.args[0], ssl_id);
    w16(&sess->req.args[4], (UWORD)fd);
    sess->req.indata  = NULL;  sess->req.inlen  = 0;
    sess->req.outdata = NULL;  sess->req.outmax = 0;
    do_rpc(sess);
    return sess->req.result;                 /* 0 or -1 */
}

/* ---- bsd_ssl_set_sni (LVO -858) -------------------------------------------
 * Store the SNI hostname for use during TLS handshake.
 * d0 = ssl_id, a0 = hostname (null-terminated), a6 = BsdBase
 * Returns: 0 on success, -1 on error.
 */
LONG bsd_ssl_set_sni(ULONG ssl_id __asm("d0"), STRPTR name __asm("a0"),
                     struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess;
    UBYTE nlen = 0;
    UBYTE i;
    sess = find_session(base);
    if (!sess || !ssl_id || !name) return -1;

    /* Measure hostname — cap at 220 to keep arglen <= 240 (wire limit). */
    while (name[nlen] && nlen < 220) nlen++;

    sess->req.opcode  = BSDOP_SSL_SET_SNI;
    sess->req.arglen  = 5 + (UWORD)nlen;    /* ssl_id(4) nlen(1) name[nlen] */
    w32(&sess->req.args[0], ssl_id);
    sess->req.args[4] = nlen;
    for (i = 0; i < nlen; i++)
        sess->req.args[5 + i] = (UBYTE)name[i];
    sess->req.indata  = NULL;  sess->req.inlen  = 0;
    sess->req.outdata = NULL;  sess->req.outmax = 0;
    do_rpc(sess);
    return sess->req.result;
}

/* ---- bsd_ssl_connect (LVO -864) -------------------------------------------
 * Perform the TLS handshake.  BLOCKS until complete.
 * d0 = ssl_id, a6 = BsdBase
 * Returns: 0 on success, -1 on error.
 */
LONG bsd_ssl_connect(ULONG ssl_id __asm("d0"), struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    if (!sess || !ssl_id) return -1;
    sess->req.opcode  = BSDOP_SSL_CONNECT;
    sess->req.arglen  = 4;
    w32(&sess->req.args[0], ssl_id);
    sess->req.indata  = NULL;  sess->req.inlen  = 0;
    sess->req.outdata = NULL;  sess->req.outmax = 0;
    do_rpc(sess);
    return sess->req.result;   /* 0 = OK, -1 = error */
}

/* ---- bsd_ssl_shutdown (LVO -870) ------------------------------------------
 * Send TLS close_notify and shut down the SSL layer.
 * d0 = ssl_id, a6 = BsdBase
 * Returns: 0 / -1.
 */
LONG bsd_ssl_shutdown(ULONG ssl_id __asm("d0"), struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    if (!sess || !ssl_id) return 0;    /* already gone: not an error */
    sess->req.opcode  = BSDOP_SSL_SHUTDOWN;
    sess->req.arglen  = 4;
    w32(&sess->req.args[0], ssl_id);
    sess->req.indata  = NULL;  sess->req.inlen  = 0;
    sess->req.outdata = NULL;  sess->req.outmax = 0;
    do_rpc(sess);
    return sess->req.result;
}

/* ---- bsd_ssl_read (LVO -876) ----------------------------------------------
 * Receive data from the TLS layer.  BLOCKS until data, EOF, or error.
 * d0 = ssl_id, a0 = buf, d1 = maxlen, a6 = BsdBase
 * Returns: bytes received (> 0), 0 on clean EOF, -1 on error.
 */
LONG bsd_ssl_read(ULONG ssl_id __asm("d0"), APTR buf __asm("a0"), LONG maxlen __asm("d1"),
                  struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    if (!sess || !ssl_id || maxlen <= 0) return -1;
    sess->req.opcode  = BSDOP_SSL_READ;
    sess->req.arglen  = 8;               /* ssl_id(4) maxlen(4) */
    w32(&sess->req.args[0], ssl_id);
    w32(&sess->req.args[4], (ULONG)maxlen);
    sess->req.indata  = NULL;  sess->req.inlen = 0;
    sess->req.outdata = buf;
    sess->req.outmax  = (ULONG)maxlen;
    do_rpc(sess);
    return sess->req.result;   /* bytes, 0 = EOF, -1 = error */
}

/* ---- bsd_ssl_write (LVO -882) ---------------------------------------------
 * Send data through the TLS layer.
 * d0 = ssl_id, a0 = buf, d1 = len, a6 = BsdBase
 * Returns: bytes written, -1 on error.
 */
LONG bsd_ssl_write(ULONG ssl_id __asm("d0"), CONST_APTR buf __asm("a0"), LONG len __asm("d1"),
                   struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    if (!sess || !ssl_id || len <= 0) return (len == 0) ? 0 : -1;
    sess->req.opcode  = BSDOP_SSL_WRITE;
    sess->req.arglen  = 4;               /* ssl_id(4); payload goes in indata */
    w32(&sess->req.args[0], ssl_id);
    sess->req.indata  = buf;
    sess->req.inlen   = (ULONG)len;
    sess->req.outdata = NULL;  sess->req.outmax = 0;
    do_rpc(sess);
    return sess->req.result;             /* bytes written or -1 */
}

/* ---- bsd_ssl_get_error (LVO -888) -----------------------------------------
 * Translate the return value of the last SSL call into an SSL_ERROR_* code.
 * d0 = ssl_id, d1 = ret, a6 = BsdBase
 * Returns: SSL_ERROR_NONE=0, SSL_ERROR_SSL=1, SSL_ERROR_ZERO_RETURN=6, etc.
 */
LONG bsd_ssl_get_error(ULONG ssl_id __asm("d0"), LONG ret __asm("d1"),
                       struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    if (!sess || !ssl_id) return 1;   /* SSL_ERROR_SSL */
    sess->req.opcode  = BSDOP_SSL_GET_ERROR;
    sess->req.arglen  = 8;            /* ssl_id(4) ret(4) */
    w32(&sess->req.args[0], ssl_id);
    w32(&sess->req.args[4], (ULONG)ret);
    sess->req.indata  = NULL;  sess->req.inlen  = 0;
    sess->req.outdata = NULL;  sess->req.outmax = 0;
    do_rpc(sess);
    return sess->req.result;   /* SSL_ERROR_NONE=0, SSL_ERROR_SSL=1, ... */
}

/* ---- getaddrinfo / freeaddrinfo (Roadshow LVO -810 / -804) ----------------
 *
 * Modern networking code (AmiSSL 5 / iBrowse 3.x) calls getaddrinfo instead
 * of gethostbyname to resolve hostnames and build the sockaddr for connect().
 *
 * The original StubRetZero at LVO -810 returned 0 (= POSIX success) but never
 * filled in *res.  iBrowse then dereferenced the unset addrinfo pointer →
 * #80000004 Illegal Instruction crash.  This is the root cause of the crash
 * after DNS_DONE that Build 15 probes isolated: no socket/SSL ops ever fired
 * because iBrowse crashed on the garbage *res before calling socket().
 *
 * Calling convention (Roadshow, AmiTCP-style register args):
 *   getaddrinfo(node, service, hints, res)(a0, a1, a2, a3) → d0 = 0/error
 *   freeaddrinfo(res)(a0)
 *
 * We implement a minimal IPv4/TCP resolver:
 *   1. Resolve node via bsd_gethostbyname_inner (reuses the Pi GETHOSTBYNAME RPC).
 *   2. Parse service as a decimal port number; fall back to well-known names.
 *   3. Fill static g_gai_info + g_gai_sa and write &g_gai_info into *res.
 *   4. Return 0 (success).
 *
 * Single static struct is safe: iBrowse is single-threaded and processes one
 * HTTPS connection at a time.  freeaddrinfo is a no-op (nothing to free).
 *
 * sockaddr_in format: AmiTCP (sin_family as WORD at offset 0, no sin_len).
 * The Pi's connect handler auto-detects AmiTCP vs BSD4.4 based on data[0].
 */

/* Minimal addrinfo layout — matches standard POSIX struct addrinfo on 32-bit. */
struct bsd_addrinfo {
    LONG   ai_flags;      /* +0  */
    LONG   ai_family;     /* +4  */
    LONG   ai_socktype;   /* +8  */
    LONG   ai_protocol;   /* +12 */
    ULONG  ai_addrlen;    /* +16 */
    STRPTR ai_canonname;  /* +20 */
    APTR   ai_addr;       /* +24  (→ g_gai_sa) */
    APTR   ai_next;       /* +28  = NULL */
};

/* AmiTCP sockaddr_in — 16 bytes, no sin_len prefix. */
struct bsd_sockaddr_in {
    UWORD sin_family;   /* +0:  AF_INET = 2 */
    UWORD sin_port;     /* +2:  port, network byte order (= host order on BE) */
    ULONG sin_addr;     /* +4:  IPv4, network byte order */
    UBYTE sin_zero[8];  /* +8:  padding */
};

static struct bsd_addrinfo   g_gai_info;
static struct bsd_sockaddr_in g_gai_sa;

/* Parse a service string: decimal number or well-known name → port.
 * Returns 0 if unrecognised (caller uses default 443). */
static UWORD parse_service(STRPTR svc)
{
    ULONG p = 0;
    if (!svc) return 0;
    /* Decimal number */
    if (svc[0] >= '0' && svc[0] <= '9') {
        while (*svc >= '0' && *svc <= '9')
            p = p * 10 + (ULONG)(*svc++ - '0');
        return (UWORD)(p & 0xFFFF);
    }
    /* Well-known service names */
    if (svc[0]=='h' && svc[1]=='t' && svc[2]=='t' && svc[3]=='p') {
        if (svc[4]=='s' && svc[5]=='\0') return 443;  /* https */
        if (svc[4]=='\0')                return 80;   /* http  */
    }
    if (svc[0]=='f' && svc[1]=='t' && svc[2]=='p' && svc[3]=='s' && svc[4]=='\0')
        return 990;  /* ftps */
    return 0;
}

LONG bsd_getaddrinfo(STRPTR node    __asm("a0"),
                     STRPTR service __asm("a1"),
                     APTR   hints   __asm("a2"),
                     struct bsd_addrinfo **res_ptr __asm("a3"),
                     struct BsdBase *base __asm("a6"))
{
    struct hostent *hp;
    UWORD port;
    UBYTE i;

    (void)hints;

    if (!node) return 6;   /* EAI_NONAME */

    /* Resolve hostname using the same GETHOSTBYNAME RPC path. */
    hp = bsd_gethostbyname_inner(node, base);
    if (!hp || !hp->h_addr_list || !hp->h_addr_list[0])
        return 11;  /* EAI_AGAIN */

    /* Determine port from service string; default 443 (HTTPS). */
    port = parse_service(service);
    if (!port) port = 443;

    /* sockaddr_in — AmiTCP format, big-endian (= network byte order on 68k). */
    g_gai_sa.sin_family = 2;                              /* AF_INET */
    g_gai_sa.sin_port   = port;                           /* already network order on BE */
    g_gai_sa.sin_addr   = *(ULONG *)hp->h_addr_list[0];  /* IPv4 from Pi, network order */
    for (i = 0; i < 8; i++) g_gai_sa.sin_zero[i] = 0;

    /* addrinfo — POSIX-standard field layout. */
    g_gai_info.ai_flags     = 0;
    g_gai_info.ai_family    = 2;    /* AF_INET */
    g_gai_info.ai_socktype  = 1;    /* SOCK_STREAM */
    g_gai_info.ai_protocol  = 0;
    g_gai_info.ai_addrlen   = 16;   /* sizeof(struct sockaddr_in) */
    g_gai_info.ai_canonname = hp->h_name;
    g_gai_info.ai_addr      = (APTR)&g_gai_sa;
    g_gai_info.ai_next      = NULL;

    if (res_ptr) *res_ptr = &g_gai_info;
    return 0;   /* success */
}

/* freeaddrinfo (LVO -804) — no-op: g_gai_info/g_gai_sa are static. */
void bsd_freeaddrinfo(APTR res __asm("a0"),
                      struct BsdBase *base __asm("a6"))
{
    (void)res; (void)base;
}
