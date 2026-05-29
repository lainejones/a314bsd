/*
 * amissl.c — AmiSSL compatibility shim for a314bsd
 *
 * This library is named amissl.library and exports a subset of the OpenSSL
 * API matching the AmiSSL calling convention.  All SSL operations are proxied
 * to the Pi via new SSL LVOs on bsdsocket.library, which in turn use
 * BSDOP_SSL_* opcodes over the A314 stream.  The Pi's Python ssl module does
 * the actual TLS using the system CA bundle — always up to date via apt.
 *
 * Architecture:
 *   App calls SSL_CTX_new()  →  amissl.library LVO
 *   amissl.library           →  JSR BSDSSL_LVO_CTX_NEW(BsdBase)
 *   bsdsocket.library        →  do_rpc(BSDOP_SSL_CTX_NEW) over A314
 *   Pi bsdsocket.py          →  ssl.SSLContext() → returns ctx_id
 *
 * Opaque handles:
 *   SSL_CTX* and SSL* are just ULONG IDs cast to pointers.
 *   ID 0 = NULL = failure.  Apps treat them as opaque and never dereference.
 *
 * *** WARNING: LVO TABLE — READ BEFORE SHIPPING ***
 * The function table in amissl_start.S MUST match the real AmiSSL FD file:
 *   AmiSSL/Developer/fd/amissl_lib.fd  (or amissl_v11_lib.fd for OpenSSL 1.1)
 * Current offsets are a PROVISIONAL placeholder for getting the infrastructure
 * working end-to-end.  Verify every LVO before claiming AmiSSL compatibility.
 */

#include <exec/types.h>
#include <exec/libraries.h>
#include <exec/memory.h>
#include <exec/lists.h>
#include <proto/exec.h>

#include "ssl_lvo.h"

/* ---- AmiSSL library base ------------------------------------------------- */

struct AmiSSLBase {
    struct Library   lib;        /* standard 34-byte library node */
    struct ExecBase *SysBase;    /* stored in Init from a6 */
    APTR             SegList;
    APTR             BsdBase;    /* bsdsocket.library base; set on first Open */
};

/* Opaque handle types: ULONG IDs cast to pointer size.
 * ID 0 = invalid.  Apps treat these as opaque; we never dereference them. */
typedef APTR SSL_CTX;
typedef APTR SSL;
typedef APTR SSL_METHOD;

/* ---- File-scope globals needed by multiple function groups ---------------- */

/* g_last_ctx_id: most recently created SSL_CTX id (from any SSL_CTX_new variant).
 * Fallback for BIO_do_connect when g_bio_ctx_id is 0.  Happens when iBrowse uses
 * BIO_new_ssl(ctx)+BIO_new_connect("host:port")+BIO_push instead of
 * the combined BIO_new_ssl_connect(ctx). */
static ULONG g_last_ctx_id = 0;

/* ---- Verify callback / mode storage (forward declarations) ----------------
 * Defined in full later; declared here so ami_ssl_open can initialise them. */

/* dummy_verify_cb: safe no-op OpenSSL verify callback (standard C calling conv).
 * Used as default g_verify_callback so any JSR through it is harmless. */
static LONG dummy_verify_cb(LONG preverify_ok, APTR x509_ctx);

/* Globals initialised by ami_ssl_open on first Open. */
static APTR g_verify_callback;   /* = dummy_verify_cb after first Open */
static LONG g_verify_mode;       /* = 0 */
static APTR g_verify_store;      /* = (APTR)1UL after first Open */

/* Build 38: last SNI hostname set via SSL_set_tlsext_host_name (SSL_ctrl cmd 55).
 * AWeb verifies the cert CN against the hostname locally; we feed this back as the
 * CN (via ASN1_STRING_data/length) so the match succeeds — the Pi already did the
 * real hostname-checked verification. */
static char g_last_sni[256];

/* ---- LVO call helpers (inline so compiler manages a6 correctly) ---------- */
/*
 * Each helper sets a6 = BsdBase, then JSRs to the bsdsocket LVO.
 * "register ... __asm("a6")" forces GCC to put the value in a6 specifically.
 * With -fomit-frame-pointer (set in Makefile) a6 is a free general register.
 *
 * Clobber list covers what bsdsocket library functions may trash:
 * d0 (return value), d1, a0, a1 per Amiga library convention.
 *
 * IMPORTANT — register aliasing fix (Build 14):
 * Earlier code had two separate 'register ... __asm("d0")' variables for the
 * d0 input and d0 output.  With -O2, GCC treats the "=d" output as the sole
 * live use of d0 and optimises away the input initialisation, leaving d0=0
 * when the JSR fires.  The fix is to use a SINGLE register variable with the
 * "+d" (read-write) constraint — GCC is then forced to load the value before
 * the instruction and to read the result afterwards.
 */

/* No d0 input — output only.  No aliasing risk. */
static inline ULONG
_bsd_call0(APTR bbase, WORD lvo)
{
    register ULONG res  __asm("d0");
    register APTR  base __asm("a6") = bbase;
    __asm volatile ("jsr %c1(%%a6)"
        : "=d"(res)
        : "i"(lvo), "a"(base)
        : "d1", "a0", "a1", "cc", "memory");
    return res;
}

/* d0 in/out, no other d-register inputs. */
static inline ULONG
_bsd_call1d(APTR bbase, WORD lvo, ULONG d0v)
{
    register ULONG d0   __asm("d0") = d0v;   /* single var — no aliasing */
    register APTR  base __asm("a6") = bbase;
    __asm volatile ("jsr %c2(%%a6)"
        : "+d"(d0)                             /* read-write: load before, result after */
        : "a"(base), "i"(lvo)
        : "d1", "a0", "a1", "cc", "memory");
    return d0;
}

/* d0 and d1 inputs, d0 output. */
static inline ULONG
_bsd_call2d(APTR bbase, WORD lvo, ULONG d0v, ULONG d1v)
{
    register ULONG d0   __asm("d0") = d0v;
    register ULONG d1   __asm("d1") = d1v;
    register APTR  base __asm("a6") = bbase;
    __asm volatile ("jsr %c3(%%a6)"
        : "+d"(d0)
        : "a"(base), "d"(d1), "i"(lvo)
        : "a0", "a1", "cc", "memory");
    return d0;
}

/* d0 = ssl_id, a0 = ptr arg, d1 = length/max */
static inline ULONG
_bsd_call_dab(APTR bbase, WORD lvo, ULONG d0v, APTR ptr, ULONG d1v)
{
    register ULONG d0   __asm("d0") = d0v;
    register ULONG d1   __asm("d1") = d1v;
    register APTR  xa0  __asm("a0") = ptr;
    register APTR  base __asm("a6") = bbase;
    __asm volatile ("jsr %c4(%%a6)"
        : "+d"(d0)
        : "a"(base), "d"(d1), "a"(xa0), "i"(lvo)
        : "a1", "cc", "memory");
    return d0;
}

/* d0 = ssl_id, a0 = string ptr */
static inline ULONG
_bsd_call_da(APTR bbase, WORD lvo, ULONG d0v, APTR ptr)
{
    register ULONG d0   __asm("d0") = d0v;
    register APTR  xa0  __asm("a0") = ptr;
    register APTR  base __asm("a6") = bbase;
    __asm volatile ("jsr %c3(%%a6)"
        : "+d"(d0)
        : "a"(base), "a"(xa0), "i"(lvo)
        : "d1", "a1", "cc", "memory");
    return d0;
}

/* ---- Amiga hostent and sockaddr_in for BIO connect path ------------------ */
/*
 * Standard POSIX structures needed to call bsdsocket.library's socket(),
 * connect(), and gethostbyname() from ami_BIO_ctrl(cmd=10 / BIO_do_connect).
 * No bsdsocket.h is included to avoid namespace conflicts with amissl types.
 */
struct ami_hostent {
    STRPTR   h_name;       /* +0: canonical hostname */
    STRPTR  *h_aliases;    /* +4: alias list (NULL-terminated) */
    LONG     h_addrtype;   /* +8: address family (AF_INET=2) */
    LONG     h_length;     /* +12: address length (4 for IPv4) */
    STRPTR  *h_addr_list;  /* +16: list of addresses (NULL-terminated) */
    /* h_addr_list[0] points to 4 bytes of IPv4 in network byte order */
};

struct ami_sockaddr_in {
    WORD  sin_family;   /* +0: AF_INET = 2 */
    UWORD sin_port;     /* +2: port in network byte order */
    ULONG sin_addr;     /* +4: IPv4 address in network byte order */
    UBYTE sin_zero[8];  /* +8: padding to 16 bytes total */
};

/* ---- BIO path bsdsocket inline helpers ----------------------------------- */
/*
 * Direct LVO calls for TCP socket operations needed by BIO_do_connect.
 * Same pattern as _bsd_call* above: a6 = BsdBase set in each helper.
 *
 * Amiga bsdsocket calling conventions (AmiTCP/Roadshow):
 *   gethostbyname(name)(a0)                 → d0 = struct hostent *
 *   socket(domain,type,proto)(d0,d1,d2)     → d0 = fd or -1
 *   connect(s,name,namelen)(d0,a0,d1)       → d0 = 0 or -1
 *
 * LVOs verified from a314bsd/amiga/lib_start.S:
 *   socket:         LVO -30
 *   connect:        LVO -54
 *   gethostbyname:  LVO -210
 */

static inline struct ami_hostent *
_bsd_gethostbyname(APTR bbase, STRPTR name)
{
    register struct ami_hostent *res __asm("d0");
    register STRPTR xname __asm("a0") = name;
    register APTR   base  __asm("a6") = bbase;
    __asm volatile ("jsr -210(%%a6)"
        : "=d"(res)
        : "a"(base), "a"(xname)
        : "d1", "a1", "cc", "memory");
    return res;
}

static inline LONG
_bsd_socket(APTR bbase, LONG domain, LONG type, LONG proto)
{
    register LONG d0   __asm("d0") = domain;  /* single var — no aliasing */
    register LONG d1   __asm("d1") = type;
    register LONG d2   __asm("d2") = proto;
    register APTR base __asm("a6") = bbase;
    __asm volatile ("jsr -30(%%a6)"
        : "+d"(d0)
        : "a"(base), "d"(d1), "d"(d2)
        : "a0", "a1", "cc", "memory");
    return d0;
}

static inline LONG
_bsd_connect(APTR bbase, LONG fd, APTR sa, LONG salen)
{
    register LONG d0   __asm("d0") = fd;      /* single var — no aliasing */
    register APTR a0   __asm("a0") = sa;
    register LONG d1   __asm("d1") = salen;
    register APTR base __asm("a6") = bbase;
    __asm volatile ("jsr -54(%%a6)"
        : "+d"(d0)
        : "a"(base), "a"(a0), "d"(d1)
        : "a1", "cc", "memory");
    return d0;
}

/* ---- Open / Close -------------------------------------------------------- */

struct AmiSSLBase *ami_ssl_open(struct AmiSSLBase *base)
{
    struct ExecBase *SysBase = base->SysBase;

    /* Initialise verify callback to the real callable dummy on first-ever open.
     * We can't use a static initializer because casting a function pointer to
     * APTR (void*) is not a constant expression in strict C99.
     * Also initialise g_verify_store to 1UL (non-NULL sentinel) so that
     * SSL_CTX_ctrl(cmd=124) always writes a valid pointer to *parg even if
     * SET_VERIFY_CERT_STORE was never called. */
    if (!g_verify_callback)
        g_verify_callback = (APTR)dummy_verify_cb;
    if (!g_verify_store)
        g_verify_store = (APTR)1UL;  /* non-NULL X509_STORE* sentinel */

    /* Open bsdsocket.library on first Open (version 4 = a314bsd minimum).
     * We keep it open as long as any caller has us open. */
    if (!base->BsdBase) {
        struct Library *bsdlib;
        base->BsdBase = OpenLibrary((STRPTR)"bsdsocket.library", 4);
        if (!base->BsdBase) return NULL;

        /* Safety: verify bsdsocket has SSL LVOs.
         * The SSL-extended bsdsocket has LIB_NEGSIZE = 888 (148 entries × 6).
         * The original a314bsd bsdsocket has LIB_NEGSIZE = 822 (137 entries × 6).
         * Calling LVO -828 on the old 137-entry table jumps to garbage memory
         * and causes an Illegal Instruction (#80000004) or worse.
         * If the deployed bsdsocket is too old, fail the Open cleanly so
         * iBrowse shows "AmiSSL unavailable" rather than crashing.
         *
         * NOTE: this guard only runs on the first Open (when BsdBase is NULL).
         * If this amissl.library hunk was loaded from disk, BsdBase is always
         * NULL on first open (ami_ssl_close zeroes it when OpenCnt reaches 0),
         * so the guard always fires for a fresh load.  The #80000004 crash can
         * only bypass this guard if an OLD amissl.library hunk — one compiled
         * without this check — is still resident in Exec's library list.
         * SOLUTION: reboot the Amiga after installing new amissl.library and
         * bsdsocket.library to flush the old hunks from memory. */
        bsdlib = (struct Library *)base->BsdBase;
        if (bsdlib->lib_NegSize < 870) {
            CloseLibrary((struct Library *)base->BsdBase);
            base->BsdBase = NULL;
            return NULL;   /* bsdsocket too old — no SSL LVOs */
        }
    }
    base->lib.lib_OpenCnt++;
    return base;
}

void ami_ssl_close(struct AmiSSLBase *base)
{
    struct ExecBase *SysBase = base->SysBase;
    base->lib.lib_OpenCnt--;
    if (base->lib.lib_OpenCnt == 0 && base->BsdBase) {
        CloseLibrary((struct Library *)base->BsdBase);
        base->BsdBase = NULL;
    }
}

/* ---- AmiSSL tag constants (from amissl/tags.h) --------------------------- */
/*
 * Used by InitAmiSSLA to locate the AmiSSL_GetAmiSSLBase tag, which is how
 * the calling app gets the amissl library base pointer in the AmiSSL 4/5 API.
 *
 * When amisslmaster's OpenAmiSSLTagList() calls InitAmiSSLA(tagList), the
 * tagList contains {AmiSSL_GetAmiSSLBase, (ULONG)&app_AmiSSLBase}.
 * We write our library base into that pointer so the app can use it.
 */
#define AMISSL_TAG_BASE         0x80000000UL   /* TAG_USER */
#define AmiSSL_GetAmiSSLBase    (AMISSL_TAG_BASE + 0x0d)
#define AmiSSL_GetAmiSSLExtBase (AMISSL_TAG_BASE + 0x0e)
#define TAG_DONE                0UL

/* ---- InitAmiSSLA / CleanupAmiSSLA --------------------------------------- */
/*
 * InitAmiSSLA(tagList)(a0)  — LVO -36
 * CleanupAmiSSLA(tagList)(a0) — LVO -42
 *
 * Two different calling conventions exist depending on AmiSSL version:
 *
 *   AmiSSL 2/3 (direct OpenLibrary path):
 *     Returns TRUE (non-zero) = success.  Apps check: if (!InitAmiSSLA(tags))
 *
 *   AmiSSL 4/5 (via amisslmaster OpenAmiSSLTagList):
 *     Returns 0 = success (error-code style).  amisslmaster checks: == 0
 *     Also MUST process AmiSSL_GetAmiSSLBase tag so the app's AmiSSLBase
 *     global gets set to our library base pointer.
 *
 * We implement the AmiSSL 4/5 convention (return 0 = success) and process
 * AmiSSL_GetAmiSSLBase, since iBrowse 3.0 uses amisslmaster + OpenAmiSSLTagList.
 *
 * The tagList may also contain AmiSSL_SocketBase, AmiSSL_ErrNoPtr, etc. —
 * we ignore these because we open our own bsdsocket.library and the Pi
 * handles the actual TLS; the Amiga side doesn't do OpenSSL socket I/O.
 */

LONG ami_InitAmiSSLA(APTR tagList_a0 __asm("a0"),
                     struct AmiSSLBase *base __asm("a6"))
{
    ULONG *tag = (ULONG *)tagList_a0;

    /* Walk the tag list and handle AmiSSL_GetAmiSSLBase + AmiSSLExtBase.
     * In the old-style path (OpenAmiSSL → InitAmiSSLA), iBrowse already has
     * the base from OpenAmiSSL's return value; it passes AmiSSL_SocketBase,
     * AmiSSL_ErrNoPtr, etc. which we safely ignore.
     * In the new-style path (OpenAmiSSLTagList), iBrowse may pass
     * AmiSSL_GetAmiSSLBase so we fill it here too. */
    if (tag) {
        while (tag[0] != TAG_DONE) {
            if (tag[0] == AmiSSL_GetAmiSSLBase ||
                tag[0] == AmiSSL_GetAmiSSLExtBase) {
                struct Library **ptr = (struct Library **)tag[1];
                if (ptr) *ptr = (struct Library *)base;
            }
            tag += 2;   /* each TagItem = {ti_Tag, ti_Data} = 8 bytes = 2 ULONGs */
        }
    }
    /* Return 0 = success — new-style AmiSSL 4/5 convention.
     *
     * iBrowse uses OpenAmiSSLTagList (LVO -60 on amisslmaster) which returns 0
     * on success, then calls InitAmiSSLA directly with the new convention where
     * 0 = success (not non-zero). */
    return 0;   /* 0 = success (new-style AmiSSL 4/5 convention) */
}

void ami_CleanupAmiSSLA(APTR tags __asm("a0"),
                         struct AmiSSLBase *base __asm("a6"))
{ (void)tags; (void)base; }

/* ---- OPENSSL_init_ssl (LVO -26568, slot 4428) --------------------------------
 * Initialises the SSL library.  Returns 1 on success, 0 on failure.
 * iBrowse 3.0 (AmiSSL 5+) calls this during startup and may abort if it
 * returns 0.  Our shim has nothing to initialise (Pi handles everything),
 * so we always return 1 = success.
 *
 * opts(d0) = OPENSSL_INIT_* flags, settings(a0) = OPENSSL_INIT_SETTINGS* or NULL
 */
LONG ami_OPENSSL_init_ssl(ULONG opts __asm("d0"), APTR settings __asm("a0"),
                           struct AmiSSLBase *base __asm("a6"))
{
    (void)opts; (void)settings;
    return 1;
}

/* ---- SSL_CTX_new_ex (LVO -32370, slot 5395) ---------------------------------
 * OpenSSL 3.x / AmiSSL 5+ version of SSL_CTX_new that takes an explicit
 * library context and property query string.  In AmiSSL 5 SDK headers,
 * SSL_CTX_new(meth) is typically compiled as SSL_CTX_new_ex(NULL,NULL,meth).
 *
 * libctx(a0) = OSSL_LIB_CTX* (NULL = global context; we ignore it)
 * propq(a1)  = const char* property query (always NULL from iBrowse; ignored)
 * meth(a2)   = const SSL_METHOD* (ignored; Pi always uses TLS_CLIENT)
 */
SSL_CTX *ami_SSL_CTX_new_ex(APTR libctx __asm("a0"), STRPTR propq __asm("a1"),
                              SSL_METHOD *meth __asm("a2"),
                              struct AmiSSLBase *base __asm("a6"))
{
    ULONG ctx_id;
    (void)libctx; (void)propq; (void)meth;
    if (!base->BsdBase) return NULL;
    ctx_id = _bsd_call0(base->BsdBase, BSDSSL_LVO_CTX_NEW);
    if (ctx_id) g_last_ctx_id = ctx_id;   /* track for BIO fallback */
    return (SSL_CTX *)ctx_id;   /* 0 = NULL = failure */
}

/* ---- OpenSSL_version (LVO -24960, slot 4160) --------------------------------
 * Returns a human-readable version string selected by the type argument.
 * iBrowse calls this to display "Secured by OpenSSL x.x.x" in connection info.
 * Returning NULL here would cause iBrowse to crash when displaying it.
 *
 * type values (OPENSSL_VERSION=0, OPENSSL_CFLAGS=1, OPENSSL_BUILT_ON=2,
 *              OPENSSL_PLATFORM=3, OPENSSL_DIR=4)
 */
STRPTR ami_OpenSSL_version(LONG type __asm("d0"),
                             struct AmiSSLBase *base __asm("a6"))
{
    static const char v0[] = "OpenSSL 3.6.2 (a314ssl shim)";
    static const char v1[] = "a314ssl";
    static const char v2[] = "built today";
    static const char v3[] = "Amiga";
    static const char v4[] = "/LIBS:";
    (void)base;
    switch (type) {
        case 0:  return (STRPTR)v0;   /* OPENSSL_VERSION */
        case 1:  return (STRPTR)v1;   /* OPENSSL_CFLAGS */
        case 2:  return (STRPTR)v2;   /* OPENSSL_BUILT_ON */
        case 3:  return (STRPTR)v3;   /* OPENSSL_PLATFORM */
        case 4:  return (STRPTR)v4;   /* OPENSSL_DIR */
        default: return (STRPTR)v0;
    }
}

/* ---- OpenSSL_version_num (LVO -24966) ------------------------------------ */
/*
 * Returns the OpenSSL version number encoded as 0xMNN00PP0 (OpenSSL 3.x scheme):
 *   (major << 28) | (minor << 20) | (patch << 4)
 *
 * We report OpenSSL 3.6.2:
 *   (3 << 28) | (6 << 20) | (2 << 4) = 0x30600020
 *
 * iBrowse 3.0 calls this after OpenAmiSSLTagList and requires the result to be
 * >= 0x30100040 (= OpenSSL 3.1.4 minimum).
 */
ULONG ami_OpenSSL_version_num(struct AmiSSLBase *base __asm("a6"))
{
    (void)base;
    return 0x30600020UL;   /* OpenSSL 3.6.2 */
}

/* ---- Method constructors ------------------------------------------------- */
/*
 * Return a dummy non-NULL token.  The Pi ignores the method value and always
 * creates ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) with the system CA bundle.
 * We return (SSL_METHOD*)1 so app NULL-checks pass.
 *
 * Note: SSLv23_client_method / SSLv23_method are #define aliases in the
 * AmiSSL headers (not separate LVO entries), so we only need TLS_* here.
 */

SSL_METHOD *ami_TLS_client_method(struct AmiSSLBase *base __asm("a6"))
{ (void)base; return (SSL_METHOD *)1UL; }

SSL_METHOD *ami_TLS_method(struct AmiSSLBase *base __asm("a6"))
{ (void)base; return (SSL_METHOD *)1UL; }

/* ---- SSL_CTX functions --------------------------------------------------- */

/* SSL_CTX_get_cert_store (LVO -8232, slot 1372) ----------------------------
 * iBrowse calls this after SSL_CTX_new to add CA certificates to the context.
 * The real function returns the internal X509_STORE* of the SSL_CTX.
 * Our Pi-side implementation handles all cert verification; there is no real
 * X509_STORE on the Amiga side.
 *
 * We return a non-NULL fake token (ctx itself cast to APTR) so that:
 *   1. iBrowse's "if (!store)" NULL guard passes
 *   2. iBrowse can pass the token back to X509_STORE_* stubs (which return 0
 *      harmlessly without dereferencing it)
 */
APTR ami_SSL_CTX_get_cert_store(SSL_CTX *ctx __asm("a0"),
                                  struct AmiSSLBase *base __asm("a6"))
{
    return ctx ? (APTR)ctx : (APTR)1UL;
}

SSL_CTX *ami_SSL_CTX_new(SSL_METHOD *meth __asm("a0"),
                          struct AmiSSLBase *base __asm("a6"))
{
    ULONG ctx_id;
    (void)meth;   /* Pi always uses TLS_client_method */
    if (!base->BsdBase) return NULL;
    ctx_id = _bsd_call0(base->BsdBase, BSDSSL_LVO_CTX_NEW);
    if (ctx_id) g_last_ctx_id = ctx_id;   /* track for BIO fallback */
    return (SSL_CTX *)ctx_id;   /* 0 = NULL = failure */
}

void ami_SSL_CTX_free(SSL_CTX *ctx __asm("a0"),
                       struct AmiSSLBase *base __asm("a6"))
{
    if (!base->BsdBase || !ctx) return;
    (void)_bsd_call1d(base->BsdBase, BSDSSL_LVO_CTX_FREE, (ULONG)ctx);
}

/* ---- Verify callback / mode storage --------------------------------------- */
/*
 * iBrowse calls SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, my_callback) and
 * then later calls SSL_CTX_get_verify_callback() / SSL_CTX_get_verify_mode()
 * / X509_STORE_get_verify_cb() to retrieve what was stored.
 *
 * CRITICAL: returning NULL causes iBrowse to call through NULL → JSR 0 →
 * crash.  Returning 1UL (non-NULL sentinel) passes iBrowse's NULL check, but
 * then iBrowse tries to CALL the returned pointer → JSR 1 → #80000004 crash.
 *
 * Fix: initialize g_verify_callback to a real callable 68K function
 * (dummy_verify_cb below) that accepts and ignores any arguments and returns
 * 1 (= certificate accepted).  The Pi performs actual TLS cert verification;
 * the dummy callback is only ever invoked if iBrowse exercises its verify
 * path on the Amiga side.
 *
 * Also: ami_SSL_CTX_ctrl cmd=123/124 (SET/GET_VERIFY_CERT_STORE) are handled
 * here.  g_verify_store stores the X509_STORE* set by cmd=123; cmd=124 writes
 * it back to *parg so iBrowse's local variable is properly initialised.
 */

/* dummy_verify_cb: no-op verify callback — definition (declared above).
 * OpenSSL verify callbacks use standard C calling convention (args on stack):
 *   int callback(int preverify_ok, X509_STORE_CTX *ctx)
 * On m68k Amiga with gcc, functions without __asm() annotations are called
 * with args pushed on the stack — matching OpenSSL's standard C convention.
 * Returning 1 = accept the certificate (Pi already verified it). */
static LONG dummy_verify_cb(LONG preverify_ok, APTR x509_ctx)
{
    (void)preverify_ok; (void)x509_ctx;
    return 1;   /* accept all certs — Pi's ssl module has already verified them */
}

/* Default return value for every UNIMPLEMENTED LVO.  StubRetZero (in
 * amissl_start.S) routes all unimplemented slots here via the WrapStubProbe
 * a6-preserving trampoline.  We return a real callable no-op (dummy_verify_cb)
 * instead of 0 so that if an app treats the result as a function pointer and
 * JSRs through it, it lands on a safe routine rather than address 0 (#80000004).
 * Args are unused (retaddr was only needed by the removed LVO-logging probe). */
APTR ami_stub_probe(ULONG retaddr __asm("d0"), struct AmiSSLBase *base __asm("a6"))
{
    (void)retaddr; (void)base;
    return (APTR)dummy_verify_cb;   /* non-NULL, callable, JSR-safe */
}

/* g_verify_store: X509_STORE* set via SSL_CTX_ctrl(cmd=123 SET_VERIFY_CERT_STORE).
 * Returned by cmd=124 (GET_VERIFY_CERT_STORE) so iBrowse's local store variable
 * is always initialised to a non-NULL value.
 * (g_verify_callback, g_verify_mode, g_verify_store all forward-declared above.) */

/* (g_last_ctx_id declared near the top of the file) */

/* Cert verify: stores callback/mode so get_verify_* can return them later. */
void ami_SSL_CTX_set_verify(SSL_CTX *ctx __asm("a0"),
                             LONG mode __asm("d0"), APTR cb __asm("a1"),
                             struct AmiSSLBase *base __asm("a6"))
{
    g_verify_mode     = mode;
    /* Store cb directly: if cb=NULL, keep the dummy (never store NULL itself —
     * the dummy_verify_cb is a safe callable fallback; real certs are verified
     * on the Pi).  If cb is a real iBrowse function, store it so we can return
     * it correctly from get_verify_callback and X509_STORE_get_verify_cb. */
    if (cb) g_verify_callback = cb;
    /* else: keep existing g_verify_callback (dummy_verify_cb or a real cb) */
    (void)ctx;
}

/* SSL_CTX_get_verify_mode (slot 1447, LVO -8682) */
LONG ami_SSL_CTX_get_verify_mode(SSL_CTX *ctx __asm("a0"),
                                  struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx;
    return g_verify_mode;
}

/* SSL_CTX_get_verify_callback (slot 1449, LVO -8694) */
APTR ami_SSL_CTX_get_verify_callback(SSL_CTX *ctx __asm("a0"),
                                      struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx;
    return g_verify_callback;   /* never NULL; sentinel 1UL if not set */
}

ULONG ami_SSL_CTX_set_options(SSL_CTX *ctx __asm("a0"), ULONG op __asm("d0"),
                               struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx;
    return op;   /* return the same options as if all were accepted */
}

LONG ami_SSL_CTX_set_cipher_list(SSL_CTX *ctx __asm("a0"), STRPTR s __asm("a1"),
                                  struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)s;
    return 1;
}

LONG ami_SSL_CTX_load_verify_locations(SSL_CTX *ctx __asm("a0"),
                                        STRPTR file __asm("a1"), STRPTR path __asm("a2"),
                                        struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)file; (void)path;
    return 1;
}

/* ---- SSL object functions ------------------------------------------------ */

SSL *ami_SSL_new(SSL_CTX *ctx __asm("a0"),
                  struct AmiSSLBase *base __asm("a6"))
{
    ULONG ssl_id;
    if (!base->BsdBase || !ctx) return NULL;
    ssl_id = _bsd_call1d(base->BsdBase, BSDSSL_LVO_NEW, (ULONG)ctx);
    return (SSL *)ssl_id;   /* 0 = NULL = failure */
}

void ami_SSL_free(SSL *ssl __asm("a0"),
                   struct AmiSSLBase *base __asm("a6"))
{
    if (!base->BsdBase || !ssl) return;
    (void)_bsd_call1d(base->BsdBase, BSDSSL_LVO_FREE, (ULONG)ssl);
}

LONG ami_SSL_set_fd(SSL *ssl __asm("a0"), LONG fd __asm("d0"),
                    struct AmiSSLBase *base __asm("a6"))
{
    if (!base->BsdBase || !ssl) return 0;
    /* Returns 1 on success (OpenSSL convention), not 0 */
    return (LONG)_bsd_call2d(base->BsdBase, BSDSSL_LVO_SET_FD,
                              (ULONG)ssl, (ULONG)fd) == 0 ? 1 : 0;
}

/* SSL_ctrl — handles all SSL_ctrl() calls.
 *
 * SSL_set_tlsext_host_name() is a C macro in the AmiSSL headers that expands to:
 *   SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, 0, (void *)hostname)
 * where SSL_CTRL_SET_TLSEXT_HOSTNAME == 55.
 *
 * We detect cmd==55 and forward the hostname to the Pi via BSDSSL_LVO_SET_SNI.
 * All other cmd values return 0 (unsupported).
 */
LONG ami_SSL_ctrl(SSL *ssl __asm("a0"), LONG cmd __asm("d0"),
                   LONG larg __asm("d1"), APTR parg __asm("a1"),
                   struct AmiSSLBase *base __asm("a6"))
{
    (void)larg;
    /* SSL_CTRL_SET_TLSEXT_HOSTNAME = 55 */
    if (cmd == 55) {
        if (!base->BsdBase || !ssl || !parg) return 0;
        /* Build 38: remember the SNI hostname (for AWeb's local cert-CN check). */
        {
            STRPTR s = (STRPTR)parg;
            UWORD  i;
            for (i = 0; i < 255 && s[i]; i++) g_last_sni[i] = s[i];
            g_last_sni[i] = 0;
        }
        return (LONG)_bsd_call_da(base->BsdBase, BSDSSL_LVO_SET_SNI,
                                   (ULONG)ssl, parg) == 0 ? 1 : 0;
    }
    return 0;   /* unsupported cmd */
}

/* SSL_CTX_ctrl — handles specific ctrl commands; stubs the rest.
 *
 * Build 20 — handle cmd=123/124 (SSL_CTRL_SET/GET_VERIFY_CERT_STORE):
 *   cmd=123: SSL_CTRL_SET_VERIFY_CERT_STORE — stores parg as the verify store.
 *            Returns 1 (success) so iBrowse proceeds instead of aborting.
 *   cmd=124: SSL_CTRL_GET_VERIFY_CERT_STORE — writes g_verify_store to *parg
 *            so iBrowse's local store variable is ALWAYS initialised to a
 *            non-NULL value (1UL sentinel or what was SET by cmd=123).
 *            Without this write, *parg is uninitialized stack garbage; iBrowse
 *            then passes the garbage to X509_STORE_get_verify_cb which returns
 *            a bad function pointer → JSR bad → #80000004.
 *            Returns 1 (store exists). */
LONG ami_SSL_CTX_ctrl(SSL_CTX *ctx __asm("a0"), LONG cmd __asm("d0"),
                       LONG larg __asm("d1"), APTR parg __asm("a1"),
                       struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)larg;

    /* SSL_CTRL_SET_VERIFY_CERT_STORE (123): iBrowse attaches an X509_STORE
     * to the SSL_CTX.  Store the pointer so GET can return it. */
    if (cmd == 123) {
        g_verify_store = parg ? parg : (APTR)1UL;
        return 1;   /* success */
    }

    /* SSL_CTRL_GET_VERIFY_CERT_STORE (124): iBrowse retrieves the store it just
     * set.  MUST write to *parg; otherwise iBrowse's local variable is
     * uninitialised and the crash follows.  Returns 1 (store exists). */
    if (cmd == 124) {
        if (parg) {
            APTR *pp = (APTR *)parg;
            *pp = g_verify_store;   /* 1UL sentinel or real store from cmd=123 */
        }
        return 1;
    }

    return 0;   /* all other cmds: unsupported, return 0 */
}

/* ---- SSL_CTX ex_data storage (LVO -9264/-9270, slots 1544/1545) ----------
 *
 * iBrowse stores application-specific data in the SSL_CTX via set_ex_data,
 * then retrieves it with get_ex_data.  Real OpenSSL supports multiple "slots"
 * identified by an index from SSL_CTX_get_ex_new_index().
 *
 * If get_ex_data returns NULL/0 and iBrowse dereferences the result as a
 * struct pointer → #80000004 Illegal Instruction crash.
 *
 * Fix: use a global array indexed by idx to store and retrieve the actual
 * values set_ex_data receives.  Per-context storage is omitted — iBrowse
 * typically uses one SSL_CTX at a time, so a global works in practice.
 *
 * Calling convention (from FD file):
 *   SSL_CTX_set_ex_data(ssl,idx,data)(a0,d0,a1)
 *   SSL_CTX_get_ex_data(ssl,idx)(a0,d0)
 */
#define AMISSL_EXDATA_MAX 8
static APTR g_ctx_exdata[AMISSL_EXDATA_MAX];

LONG ami_SSL_CTX_set_ex_data(SSL_CTX *ctx __asm("a0"),
                               LONG idx  __asm("d0"),
                               APTR data __asm("a1"),
                               struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx;
    if (idx >= 0 && (ULONG)idx < AMISSL_EXDATA_MAX)
        g_ctx_exdata[(ULONG)idx] = data;
    return 1;   /* success */
}

APTR ami_SSL_CTX_get_ex_data(SSL_CTX *ctx __asm("a0"),
                               LONG idx  __asm("d0"),
                               struct AmiSSLBase *base __asm("a6"))
{
    APTR v;
    (void)ctx;
    if (idx >= 0 && (ULONG)idx < AMISSL_EXDATA_MAX) {
        v = g_ctx_exdata[(ULONG)idx];
        /* Build 18: never return NULL — static array starts zero-initialised;
         * returning 0 hands iBrowse a NULL struct pointer which it then
         * dereferences for a function pointer → JSR 0 → #80000004.
         * Return 1UL as a safe sentinel when no data has been stored yet. */
        return v ? v : (APTR)1UL;
    }
    return (APTR)1UL;   /* non-NULL sentinel for out-of-range idx */
}

/* ---- BIO SSL path (LVO -1728 to -2070, slots 288-345; -8166 to -8184, slots 1361-1364) ---
 *
 * iBrowse 3.x uses OpenSSL's BIO abstraction for HTTPS connections:
 *
 *   ctx = SSL_CTX_new(method)
 *   bio = BIO_new_ssl_connect(ctx)            ← slot 1363
 *   BIO_set_conn_hostname(bio,"host:443")     ← BIO_ctrl(bio,100,0,"host:443")
 *   BIO_do_connect(bio)                       ← BIO_ctrl(bio,10,0,NULL)
 *   BIO_get_ssl(bio,&ssl)                     ← BIO_ctrl(bio,110,0,&ssl)
 *   BIO_read(bio,buf,len)  / BIO_write(...)   ← slots 292, 294
 *
 * BIO_do_connect (cmd=10) does the complete TCP+TLS handshake:
 *   gethostbyname → socket → connect → SSL_new → SSL_set_fd → SSL_set_sni → SSL_connect
 *
 * State is kept in globals (safe: iBrowse is single-threaded, one BIO at a time).
 *
 * Wrapper requirement: ami_BIO_ctrl / ami_BIO_read / ami_BIO_write call bsdsocket,
 * which clobbers a6.  Each is invoked via WrapBIOCtrl / WrapBIORead / WrapBIOWrite
 * in amissl_start.S, which saves/restores a6 (AmiSSLBase) around the call.
 * ami_BIO_new_ssl_connect does NOT call bsdsocket so it needs no wrapper.
 */

/* BIO global state — one active BIO at a time */
static ULONG g_bio_ctx_id        = 0;   /* SSL_CTX id (from BIO_new_ssl_connect or BIO_new_ssl) */
static ULONG g_bio_ssl_id        = 0;   /* SSL id (created in BIO_do_connect) */
static LONG  g_bio_fd            = -1;  /* socket fd (created in BIO_do_connect) */
static char  g_bio_hostname[256] = {0}; /* hostname (set by BIO_ctrl cmd=100 or BIO_new_connect) */
static UWORD g_bio_port          = 443; /* port (set by BIO_ctrl cmd=100 or BIO_new_connect) */


/* ---- BIO_f_ssl (slot 1361, LVO -8166) ------------------------------------ */
APTR ami_BIO_f_ssl(struct AmiSSLBase *base __asm("a6"))
{
    (void)base;
    return (APTR)1UL;   /* non-NULL SSL BIO method sentinel */
}

/* ---- BIO_new_ssl (slot 1362, LVO -8172) ---------------------------------- */
/* iBrowse may call BIO_new_ssl(ctx,1) + BIO_new_connect("host:port") + BIO_push
 * instead of BIO_new_ssl_connect.  Store ctx_id so BIO_do_connect can use it. */
APTR ami_BIO_new_ssl(SSL_CTX *ctx __asm("a0"), LONG client __asm("d0"),
                      struct AmiSSLBase *base __asm("a6"))
{
    (void)client; (void)base;
    if (ctx) {
        g_bio_ctx_id  = (ULONG)ctx;
        g_bio_ssl_id  = 0;
        g_bio_fd      = -1;
    }
    return (APTR)1UL;
}

/* ---- BIO_new_ssl_connect (slot 1363, LVO -8178) --------------------------
 * Save ctx_id and initialise BIO global state.  Return a non-NULL BIO handle. */
APTR ami_BIO_new_ssl_connect(SSL_CTX *ctx __asm("a0"),
                               struct AmiSSLBase *base __asm("a6"))
{
    (void)base;
    g_bio_ctx_id      = (ULONG)ctx;
    g_bio_ssl_id      = 0;
    g_bio_fd          = -1;
    g_bio_port        = 443;
    g_bio_hostname[0] = '\0';
    return (APTR)1UL;   /* non-NULL BIO handle sentinel */
}

/* ---- BIO_new_buffer_ssl_connect (slot 1364, LVO -8184) ------------------- */
APTR ami_BIO_new_buffer_ssl_connect(SSL_CTX *ctx __asm("a0"),
                                     struct AmiSSLBase *base __asm("a6"))
{
    /* Delegate: same BIO state as BIO_new_ssl_connect */
    return ami_BIO_new_ssl_connect(ctx, base);
}

/* ---- BIO_new (slot 288, LVO -1728) --------------------------------------- */
APTR ami_BIO_new(APTR method __asm("a0"), struct AmiSSLBase *base __asm("a6"))
{
    (void)method; (void)base;
    return (APTR)1UL;
}

/* ---- BIO_ctrl (slot 297, LVO -1782) — called via WrapBIOCtrl -------------
 * Calling convention: BIO_ctrl(bp,cmd,larg,parg)(a0,d0,d1,a1) → LONG
 *
 * Handles:
 *   cmd=100  BIO_C_SET_CONNECT: parse/store hostname[:port] or port string
 *   cmd= 11  BIO_CTRL_FLUSH: no-op, return success
 *   cmd=110  BIO_C_GET_SSL: write ssl_id into *parg
 *   cmd= 10  BIO_C_DO_STATE_MACHINE (BIO_do_connect): full TCP+TLS handshake
 */
LONG ami_BIO_ctrl(APTR bio __asm("a0"), LONG cmd __asm("d0"),
                   LONG larg __asm("d1"), APTR parg __asm("a1"),
                   struct AmiSSLBase *base __asm("a6"))
{
    (void)bio;

    /* --- BIO_C_SET_CONNECT (100): set hostname or port --- */
    if (cmd == 100) {
        if (larg == 0 && parg) {
            /* hostname or "hostname:port" */
            STRPTR src = (STRPTR)parg;
            UWORD  i   = 0;
            while (i < 255 && src[i] && src[i] != ':') {
                g_bio_hostname[i] = src[i];
                i++;
            }
            g_bio_hostname[i] = '\0';
            if (src[i] == ':') {
                STRPTR ps = src + i + 1;
                UWORD  p  = 0;
                while (*ps >= '0' && *ps <= '9')
                    p = (UWORD)(p * 10 + (*ps++ - '0'));
                if (p) g_bio_port = p;
            }
        } else if (larg == 1 && parg) {
            /* separate port string, e.g. "443" */
            STRPTR ps = (STRPTR)parg;
            UWORD  p  = 0;
            while (*ps >= '0' && *ps <= '9')
                p = (UWORD)(p * 10 + (*ps++ - '0'));
            if (p) g_bio_port = p;
        }
        return 1;
    }

    /* --- BIO_CTRL_FLUSH (11): flush — always succeeds --- */
    if (cmd == 11) {
        return 1;
    }

    /* --- BIO_C_GET_SSL (110): write ssl_id into *parg --- */
    if (cmd == 110) {
        if (parg) {
            ULONG *pp = (ULONG *)parg;
            *pp = g_bio_ssl_id;   /* 0 if not yet connected */
        }
        return (g_bio_ssl_id != 0) ? 1 : 0;
    }

    /* --- BIO_C_DO_STATE_MACHINE (10): BIO_do_connect — full TCP+TLS handshake --- */
    if (cmd == 10) {
        struct ami_hostent    *he;
        struct ami_sockaddr_in sa;
        LONG                   fd;
        ULONG                  ssl_id;
        ULONG                  ip_addr;  /* IPv4 in network byte order */
        APTR                   bbase;
        ULONG                  ctx_to_use;

        if (!base->BsdBase || !g_bio_hostname[0]) return 0;

        /* Use whichever ctx_id is available; prefer the one set by BIO_new_ssl_connect
         * or BIO_new_ssl, fall back to the most recently created SSL_CTX. */
        ctx_to_use = g_bio_ctx_id ? g_bio_ctx_id : g_last_ctx_id;
        if (!ctx_to_use) return 0;

        bbase = base->BsdBase;

        /* 1. DNS resolution — sends BSDOP_GETHOSTBYNAME to Pi.
         * Read IP immediately before any other bsdsocket call might invalidate
         * the static hostent buffer returned by gethostbyname. */
        he = _bsd_gethostbyname(bbase, (STRPTR)g_bio_hostname);

        if (!he || !he->h_addr_list || !he->h_addr_list[0]) return 0;
        ip_addr = *(ULONG *)he->h_addr_list[0];   /* 4 bytes, network byte order */

        /* 2. Create TCP socket */
        fd = _bsd_socket(bbase, 2 /*AF_INET*/, 1 /*SOCK_STREAM*/, 0);
        if (fd < 0) return 0;

        /* 3. TCP connect to host:port
         * 68k is big-endian = network byte order; no byte swap needed for port or IP. */
        sa.sin_family      = 2;   /* AF_INET */
        sa.sin_port        = g_bio_port;
        sa.sin_addr        = ip_addr;
        sa.sin_zero[0]     = 0; sa.sin_zero[1] = 0;
        sa.sin_zero[2]     = 0; sa.sin_zero[3] = 0;
        sa.sin_zero[4]     = 0; sa.sin_zero[5] = 0;
        sa.sin_zero[6]     = 0; sa.sin_zero[7] = 0;
        if (_bsd_connect(bbase, fd, (APTR)&sa, 16) != 0) return 0;

        /* 4. Create SSL object from ctx_id (from BIO_new_ssl_connect, BIO_new_ssl,
         *    or most-recently-created SSL_CTX — whichever is available) */
        ssl_id = _bsd_call1d(bbase, BSDSSL_LVO_NEW, ctx_to_use);
        if (!ssl_id) return 0;

        /* 5. Attach socket fd to SSL */
        (void)_bsd_call2d(bbase, BSDSSL_LVO_SET_FD, ssl_id, (ULONG)fd);

        /* 6. Set SNI hostname */
        (void)_bsd_call_da(bbase, BSDSSL_LVO_SET_SNI, ssl_id, (APTR)g_bio_hostname);

        /* 7. TLS handshake (blocks until Pi reports success or failure) */
        if (_bsd_call1d(bbase, BSDSSL_LVO_CONNECT, ssl_id) != 0) {
            /* Handshake failed; keep ssl_id/fd for error reporting */
            g_bio_ssl_id = ssl_id;
            g_bio_fd     = fd;
            return 0;   /* failure */
        }

        g_bio_ssl_id = ssl_id;
        g_bio_fd     = fd;
        return 1;   /* success */
    }

    return 0;   /* unsupported cmd */
}

/* ---- BIO_new_connect (slot 345, LVO -2070) --------------------------------
 * Creates a TCP connect BIO for a given "hostname:port" string.
 * iBrowse may use this + BIO_new_ssl + BIO_push instead of BIO_new_ssl_connect.
 * We parse the hostname:port here and store it so BIO_do_connect can use it.
 * Does NOT call bsdsocket (so no wrapper needed). */
APTR ami_BIO_new_connect(STRPTR host_port __asm("a0"),
                          struct AmiSSLBase *base __asm("a6"))
{
    (void)base;
    g_bio_ssl_id  = 0;
    g_bio_fd      = -1;
    g_bio_port    = 443;
    g_bio_hostname[0] = '\0';

    if (host_port) {
        STRPTR src = host_port;
        UWORD  i   = 0;
        /* Copy hostname up to ':' or end of string */
        while (i < 255 && src[i] && src[i] != ':') {
            g_bio_hostname[i] = src[i];
            i++;
        }
        g_bio_hostname[i] = '\0';
        /* Parse port if present */
        if (src[i] == ':') {
            STRPTR ps = src + i + 1;
            UWORD  p  = 0;
            while (*ps >= '0' && *ps <= '9')
                p = (UWORD)(p * 10 + (*ps++ - '0'));
            if (p) g_bio_port = p;
        }
    }
    return (APTR)1UL;
}

/* ---- BIO_read (slot 292, LVO -1752) — called via WrapBIORead -------------
 * Calling convention: BIO_read(b,data,len)(a0,a1,d0) → LONG
 * Proxies through g_bio_ssl_id → BSDSSL_LVO_READ (SSL_read on Pi). */
LONG ami_BIO_read(APTR bio __asm("a0"), APTR buf __asm("a1"), LONG len __asm("d0"),
                  struct AmiSSLBase *base __asm("a6"))
{
    (void)bio;
    if (!base->BsdBase || !g_bio_ssl_id || len <= 0) return -1;
    return (LONG)_bsd_call_dab(base->BsdBase, BSDSSL_LVO_READ,
                                g_bio_ssl_id, buf, (ULONG)len);
}

/* ---- BIO_write (slot 294, LVO -1764) — called via WrapBIOWrite -----------
 * Calling convention: BIO_write(b,data,len)(a0,a1,d0) → LONG
 * Proxies through g_bio_ssl_id → BSDSSL_LVO_WRITE (SSL_write on Pi). */
LONG ami_BIO_write(APTR bio __asm("a0"), CONST_APTR buf __asm("a1"), LONG len __asm("d0"),
                   struct AmiSSLBase *base __asm("a6"))
{
    (void)bio;
    if (!base->BsdBase || !g_bio_ssl_id || len <= 0) return -1;
    return (LONG)_bsd_call_dab(base->BsdBase, BSDSSL_LVO_WRITE,
                                g_bio_ssl_id, (APTR)buf, (ULONG)len);
}

/* ---- SSL_CTX_get_ssl_method (LVO -24216, slot 4036) ----------------------
 * Returns the SSL_METHOD stored in the context.
 * Returns non-NULL sentinel so NULL dereferences don't crash iBrowse.
 * Calling convention: SSL_CTX_get_ssl_method(ctx)(a0) → SSL_METHOD*
 */
SSL_METHOD *ami_SSL_CTX_get_ssl_method(SSL_CTX *ctx __asm("a0"),
                                        struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return (SSL_METHOD *)1UL;
}

LONG ami_SSL_connect(SSL *ssl __asm("a0"),
                     struct AmiSSLBase *base __asm("a6"))
{
    /* Returns 1 on success (OpenSSL convention), <=0 on error */
    LONG r;
    if (!base->BsdBase || !ssl) return -1;
    r = (LONG)_bsd_call1d(base->BsdBase, BSDSSL_LVO_CONNECT, (ULONG)ssl);
    return (r == 0) ? 1 : -1;
}

LONG ami_SSL_shutdown(SSL *ssl __asm("a0"),
                       struct AmiSSLBase *base __asm("a6"))
{
    if (!base->BsdBase || !ssl) return -1;
    return (LONG)_bsd_call1d(base->BsdBase, BSDSSL_LVO_SHUTDOWN, (ULONG)ssl);
}

LONG ami_SSL_read(SSL *ssl __asm("a0"), APTR buf __asm("a1"), LONG num __asm("d0"),
                  struct AmiSSLBase *base __asm("a6"))
{
    if (!base->BsdBase || !ssl || num <= 0) return -1;
    return (LONG)_bsd_call_dab(base->BsdBase, BSDSSL_LVO_READ,
                                (ULONG)ssl, buf, (ULONG)num);
}

LONG ami_SSL_write(SSL *ssl __asm("a0"), CONST_APTR buf __asm("a1"), LONG num __asm("d0"),
                   struct AmiSSLBase *base __asm("a6"))
{
    if (!base->BsdBase || !ssl || num <= 0) return -1;
    return (LONG)_bsd_call_dab(base->BsdBase, BSDSSL_LVO_WRITE,
                                (ULONG)ssl, (APTR)buf, (ULONG)num);
}

LONG ami_SSL_get_error(SSL *ssl __asm("a0"), LONG ret __asm("d0"),
                       struct AmiSSLBase *base __asm("a6"))
{
    if (!base->BsdBase || !ssl) return 1; /* SSL_ERROR_SSL */
    return (LONG)_bsd_call2d(base->BsdBase, BSDSSL_LVO_GET_ERROR,
                              (ULONG)ssl, (ULONG)ret);
}

/* ---- Error / misc stubs -------------------------------------------------- */

ULONG ami_ERR_get_error(struct AmiSSLBase *base __asm("a6"))
{
    (void)base;
    return 0;   /* 0 = no error in queue (safe; iBrowse treats 0 as "no SSL error") */
}

ULONG ami_ERR_peek_error(struct AmiSSLBase *base __asm("a6"))
{ (void)base; return 0; }

void ami_ERR_clear_error(struct AmiSSLBase *base __asm("a6"))
{ (void)base; }

STRPTR ami_ERR_error_string(ULONG e __asm("d0"), STRPTR buf __asm("a0"),
                              struct AmiSSLBase *base __asm("a6"))
{
    static const char msg[] = "a314ssl error";
    (void)e; (void)base;
    if (buf) {
        UWORD i;
        for (i = 0; i < sizeof(msg); i++) buf[i] = msg[i];
        return buf;
    }
    return (STRPTR)msg;
}

LONG ami_SSL_pending(SSL *ssl __asm("a0"),
                     struct AmiSSLBase *base __asm("a6"))
{ (void)ssl; (void)base; return 0; }

APTR ami_SSL_get_peer_certificate(SSL *ssl __asm("a0"),
                                   struct AmiSSLBase *base __asm("a6"))
{
    /* Real cert is on Pi; Amiga side has no X509 struct.
     * Return non-NULL sentinel — if iBrowse dereferences NULL → crash. */
    (void)ssl; (void)base;
    return (APTR)1UL;
}

LONG ami_SSL_get_verify_result(SSL *ssl __asm("a0"),
                                struct AmiSSLBase *base __asm("a6"))
{ (void)ssl; (void)base; return 0; /* X509_V_OK */ }

LONG ami_SSL_CTX_set_default_verify_paths(SSL_CTX *ctx __asm("a0"),
                                           struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return 1;
}

void ami_SSL_set_verify(SSL *ssl __asm("a0"), LONG mode __asm("d0"),
                         APTR cb __asm("a1"),
                         struct AmiSSLBase *base __asm("a6"))
{
    /* Store into the same globals so SSL_get_verify_callback returns the right value. */
    g_verify_mode     = mode;
    g_verify_callback = cb ? cb : (APTR)dummy_verify_cb;
    (void)ssl; (void)base;
}

/* ---- SSL* object getter functions returning callbacks / pointers ------------ */
/*
 * These are the SSL* counterparts to the SSL_CTX* getters above.
 * After SSL_new(), iBrowse reads back verify callbacks and CTX pointers.
 * Returning NULL causes JSR 0 → #80000004 crash.
 *
 * Slot assignments (verified from FD file ##bias 8316, line 1201):
 *   SSL_get_verify_callback  slot 1403  LVO  -8418
 *   SSL_get_SSL_CTX          slot 1532  LVO  -9192
 *   SSL_get_info_callback    slot 1534  LVO  -9204
 */

/* SSL_get_verify_callback (slot 1403, LVO -8418) — per-SSL* object getter.
 * Called after SSL_new to retrieve the inherited verify callback.
 * Was StubRetZero (NULL) → iBrowse calls through NULL → JSR 0 → #80000004! */
APTR ami_SSL_get_verify_callback(SSL *ssl __asm("a0"),
                                  struct AmiSSLBase *base __asm("a6"))
{
    (void)ssl; (void)base;
    return g_verify_callback;   /* never NULL; sentinel 1UL if not set */
}

/* SSL_get_SSL_CTX (slot 1532, LVO -9192) — returns SSL_CTX* from SSL*.
 * iBrowse calls this to retrieve ctx for SSL_CTX_get_ex_data / verify ops.
 * Was StubRetZero (NULL) → iBrowse passes NULL to SSL_CTX_* → crash!
 * Return sentinel 1UL — ami_SSL_CTX_get_ex_data ignores the ctx arg anyway. */
SSL_CTX *ami_SSL_get_SSL_CTX(SSL *ssl __asm("a0"),
                               struct AmiSSLBase *base __asm("a6"))
{
    (void)ssl; (void)base;
    return (SSL_CTX *)1UL;   /* non-NULL sentinel; real ctx unavailable client-side */
}

/* SSL_get_info_callback (slot 1534, LVO -9204) — per-SSL* info callback getter.
 * Was StubRetZero (NULL) → if iBrowse calls through NULL → JSR 0 → #80000004! */
APTR ami_SSL_get_info_callback(SSL *ssl __asm("a0"),
                                struct AmiSSLBase *base __asm("a6"))
{
    (void)ssl; (void)base;
    return (APTR)dummy_verify_cb;   /* Build 21: real callable no-op, JSR-safe */
}

/* ---- SSL_CTX / X509_STORE getter functions returning callbacks -------------- */
/*
 * These functions return function pointers or opaque data that iBrowse may call
 * through directly.  Returning 0 (= StubRetZero) causes JSR 0 → #80000004 crash.
 *
 * Slot assignments (from amissl_lib.fd, verified):
 *   SSL_CTX_get_info_callback              slot 3232  LVO -19392
 *   SSL_CTX_get_default_passwd_cb          slot 4593  LVO -27558
 *   SSL_CTX_get_default_passwd_cb_userdata slot 4594  LVO -27564
 *   X509_STORE_get_verify                  slot 4796  LVO -28776
 *   X509_STORE_get_verify_cb              slot 4797  LVO -28782
 */

/* ASN1_STRING_length (slot 36, LVO -216) — length of an ASN1 string.  In AWeb's
 * hostname check this is the length of the cert CN; we return strlen(g_last_sni)
 * so the CN matches the SNI host.  (Other ASN1 uses are rare in these clients.) */
LONG ami_ASN1_STRING_length(APTR asn1 __asm("a0"), struct AmiSSLBase *base __asm("a6"))
{
    UWORD n = 0;
    (void)asn1; (void)base;
    while (g_last_sni[n]) n++;
    return (LONG)n;
}

/* ASN1_STRING_data (slot 39, LVO -234) — bytes of an ASN1 string = the cert CN,
 * which we report as the SNI hostname so AWeb's CN-vs-host compare matches. */
APTR ami_ASN1_STRING_data(APTR asn1 __asm("a0"), struct AmiSSLBase *base __asm("a6"))
{
    (void)asn1; (void)base;
    return (APTR)g_last_sni;
}

/* X509_verify_cert (slot 1974, LVO -11844) — verify the cert chain in an
 * X509_STORE_CTX.  Returns 1 on success.  AWeb does its OWN local chain
 * verification after connect; but the Pi already performed the real verification
 * during the TLS handshake (CERT_REQUIRED + system CA bundle), so reporting 1
 * (verified) here is correct for our architecture and stops AWeb's cert prompt. */
LONG ami_X509_verify_cert(APTR ctx __asm("a0"), struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return 1;
}

/* X509_STORE_CTX_init (slot 2025, LVO -12150) — initialise a verify context.
 * (ctx, store, cert, chain)(a0,a1,a2,a3).  Returns 1 on success.  AWeb checks
 * this == 1 before calling X509_verify_cert. */
LONG ami_X509_STORE_CTX_init(APTR ctx __asm("a0"), APTR store __asm("a1"),
                              APTR cert __asm("a2"), APTR chain __asm("a3"),
                              struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)store; (void)cert; (void)chain; (void)base;
    return 1;
}

/* OPENSSL_sk_num (slot 1554, LVO -9324) — number of elements in a stack.
 * AWeb iterates `for(i=0;i<OPENSSL_sk_num(s);i++) OPENSSL_sk_value(s,i)`.  Our
 * StubRetZero returned a huge value -> ~infinite loop spinning on sk_value.
 * Return 0 = empty stack so the loop body never runs. */
LONG ami_OPENSSL_sk_num(APTR sk __asm("a0"), struct AmiSSLBase *base __asm("a6"))
{
    (void)sk; (void)base;
    return 0;
}

/* OPENSSL_sk_value (slot 1555, LVO -9330) — element at index; return NULL. */
APTR ami_OPENSSL_sk_value(APTR sk __asm("a0"), LONG idx __asm("d0"),
                           struct AmiSSLBase *base __asm("a6"))
{
    (void)sk; (void)idx; (void)base;
    return (APTR)0;
}

/* SSL_CTX_up_ref (slot 4450, LVO -26700) — increments the SSL_CTX reference
 * count, returns int 1 on success.  AWeb 3.6b8 calls this (its handle is shared)
 * and a higher-level loop spins on it while our StubRetZero returned a high
 * pointer; the correct return is 1.  The Pi keeps contexts persistent (global,
 * never freed during the debug phase) so no real refcount bookkeeping is needed. */
LONG ami_SSL_CTX_up_ref(APTR ctx __asm("a0"),
                         struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return 1;
}

/* SSL_CTX_sess_get_get_cb (slot 3229, LVO -19374) */
APTR ami_SSL_CTX_sess_get_get_cb(SSL_CTX *ctx __asm("a0"),
                                   struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return (APTR)dummy_verify_cb;   /* Build 21: real callable no-op, JSR-safe */
}

/* SSL_CTX_get_info_callback (slot 3232, LVO -19392) */
APTR ami_SSL_CTX_get_info_callback(SSL_CTX *ctx __asm("a0"),
                                    struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return (APTR)dummy_verify_cb;   /* Build 21: real callable no-op, JSR-safe */
}

/* SSL_CTX_sess_get_new_cb (slot 3233, LVO -19398) */
APTR ami_SSL_CTX_sess_get_new_cb(SSL_CTX *ctx __asm("a0"),
                                   struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return (APTR)dummy_verify_cb;   /* Build 21: real callable no-op, JSR-safe */
}

/* SSL_CTX_get_client_cert_cb (slot 3234, LVO -19404) */
APTR ami_SSL_CTX_get_client_cert_cb(SSL_CTX *ctx __asm("a0"),
                                     struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return (APTR)dummy_verify_cb;   /* Build 21: real callable no-op, JSR-safe */
}

/* SSL_CTX_sess_get_remove_cb (slot 3235, LVO -19410) */
APTR ami_SSL_CTX_sess_get_remove_cb(SSL_CTX *ctx __asm("a0"),
                                     struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return (APTR)dummy_verify_cb;   /* Build 21: real callable no-op, JSR-safe */
}

/* ---- Build 5: fix NULL-returning getter slots 3230, 3236, 3237 ---------------
 *
 * The FD file (##bias 19362 → slot 3227) shows the true slot layout:
 *   Slot 3229 = SSL_CTX_sess_set_new_cb      (SETTER — stub OK)
 *   Slot 3230 = SSL_CTX_sess_get_get_cb      (GETTER — was StubRetZero → CRASH!)
 *   Slot 3231 = SSL_CTX_sess_set_get_cb      (SETTER — stub OK)
 *   Slot 3232 = SSL_CTX_get_info_callback    (GETTER — fixed in build 3)
 *   Slot 3233 = SSL_CTX_set_client_cert_cb   (SETTER — stub OK)
 *   Slot 3234 = SSL_CTX_sess_set_remove_cb   (SETTER — stub OK)
 *   Slot 3235 = SSL_CTX_sess_get_new_cb      (GETTER — fixed in build 3, mislabeled)
 *   Slot 3236 = SSL_CTX_get_client_cert_cb   (GETTER — was StubRetZero → CRASH!)
 *   Slot 3237 = SSL_CTX_sess_get_remove_cb   (GETTER — was StubRetZero → CRASH!)
 *
 * Pattern: iBrowse saves old callbacks before setting new ones, then later calls
 * through the saved pointers.  NULL saved ptr → JSR 0 → #80000004.
 * We use suffix _real to distinguish from the mislabeled build-3 functions.
 */

/* SSL_CTX_sess_get_get_cb (slot 3230, LVO -19380) — GETTER for session-get callback. */
APTR ami_SSL_CTX_sess_get_get_cb_real(SSL_CTX *ctx __asm("a0"),
                                       struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return (APTR)dummy_verify_cb;   /* Build 21: real callable no-op, JSR-safe */
}

/* SSL_CTX_get_client_cert_cb (slot 3236, LVO -19416) — GETTER for client-cert callback. */
APTR ami_SSL_CTX_get_client_cert_cb_real(SSL_CTX *ctx __asm("a0"),
                                          struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return (APTR)dummy_verify_cb;   /* Build 21: real callable no-op, JSR-safe */
}

/* SSL_CTX_sess_get_remove_cb (slot 3237, LVO -19422) — GETTER for session-remove callback. */
APTR ami_SSL_CTX_sess_get_remove_cb_real(SSL_CTX *ctx __asm("a0"),
                                          struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return (APTR)dummy_verify_cb;   /* Build 21: real callable no-op, JSR-safe */
}

/* SSL_CTX_get_default_passwd_cb (slot 4593, LVO -27558) */
APTR ami_SSL_CTX_get_default_passwd_cb(SSL_CTX *ctx __asm("a0"),
                                        struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return (APTR)dummy_verify_cb;   /* Build 21: real callable no-op, JSR-safe */
}

/* SSL_CTX_get_default_passwd_cb_userdata (slot 4594, LVO -27564) */
APTR ami_SSL_CTX_get_default_passwd_cb_userdata(SSL_CTX *ctx __asm("a0"),
                                                  struct AmiSSLBase *base __asm("a6"))
{
    (void)ctx; (void)base;
    return (APTR)1UL;   /* non-NULL sentinel */
}

/* X509_STORE_get_verify (slot 4796, LVO -28776) */
APTR ami_X509_STORE_get_verify(APTR store __asm("a0"),
                                struct AmiSSLBase *base __asm("a6"))
{
    (void)store; (void)base;
    return (APTR)dummy_verify_cb;   /* real callable no-op, JSR-safe */
}

/* X509_STORE_get_verify_cb (slot 4797, LVO -28782)
 * Returns the verify callback stored by SSL_CTX_set_verify.
 * CRITICAL: must return a callable function, not NULL or 1UL sentinel.
 *   NULL  → iBrowse might JSR NULL → crash
 *   1UL   → iBrowse's NULL check passes, then JSR 1 → crash on 68020
 *   dummy_verify_cb → real 68K function, safe to call, returns 1 (accept) */
APTR ami_X509_STORE_get_verify_cb(APTR store __asm("a0"),
                                   struct AmiSSLBase *base __asm("a6"))
{
    (void)store; (void)base;
    return g_verify_callback;   /* dummy_verify_cb or real cb — always callable */
}

/* ---- SSL cipher / version info stubs ----------------------------------------
 * iBrowse calls these after SSL_connect to populate the padlock info display.
 * All return non-NULL values so iBrowse's string handling code doesn't crash.
 *
 * SSL_CIPHER* is an opaque handle; we use a sentinel value (1) so that
 * SSL_CIPHER_get_* functions can recognise it as "the dummy TLS 1.3 cipher".
 * iBrowse treats it as fully opaque and only passes it back to other
 * SSL_CIPHER_get_* functions — never dereferences it directly.
 *
 * LVO table slots:
 *   SSL_get_current_cipher  slot 1377  LVO  -8262
 *   SSL_CIPHER_get_bits     slot 1378  LVO  -8268
 *   SSL_CIPHER_get_version  slot 1379  LVO  -8274
 *   SSL_CIPHER_get_name     slot 1380  LVO  -8280
 *   SSL_get_version         slot 1481  LVO  -8886
 */

APTR ami_SSL_get_current_cipher(SSL *ssl __asm("a0"),
                                 struct AmiSSLBase *base __asm("a6"))
{ (void)ssl; (void)base; return (APTR)1UL; /* dummy non-NULL sentinel */ }

LONG ami_SSL_CIPHER_get_bits(APTR cipher __asm("a0"), LONG *alg_bits __asm("a1"),
                              struct AmiSSLBase *base __asm("a6"))
{
    (void)base;
    if (!cipher) return 0;
    if (alg_bits) *alg_bits = 256;
    return 256;   /* AES-256 equivalent */
}

STRPTR ami_SSL_CIPHER_get_version(APTR cipher __asm("a0"),
                                   struct AmiSSLBase *base __asm("a6"))
{
    static const char ver[] = "TLSv1.3";
    (void)base;
    return (STRPTR)(cipher ? ver : ver);   /* always non-NULL */
}

STRPTR ami_SSL_CIPHER_get_name(APTR cipher __asm("a0"),
                                struct AmiSSLBase *base __asm("a6"))
{
    static const char name[] = "TLS_AES_256_GCM_SHA384";
    static const char none[] = "(NONE)";
    (void)base;
    return (STRPTR)(cipher ? name : none);
}

/* SSL_get_version: always "TLSv1.3" — Pi only negotiates TLS 1.2+ anyway */
STRPTR ami_SSL_get_version(SSL *ssl __asm("a0"),
                            struct AmiSSLBase *base __asm("a6"))
{
    static const char ver[] = "TLSv1.3";
    (void)ssl; (void)base;
    return (STRPTR)ver;
}
