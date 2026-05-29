/*
 * bsdsocket_main.c — unity build: a314bsd bsdsocket.library + SSL extension
 *
 * This file is the single compilation unit for the extended bsdsocket.library.
 * It works in two steps:
 *
 *   1. #include the original bsdsocket.c verbatim — unchanged, from its
 *      canonical location in the a314bsd repo.  This brings in all the
 *      library functions AND the static internal helpers:
 *        find_session(), do_rpc(), w16(), w32(), propagate_errno()
 *
 *   2. #include bsd_ssl_stubs.c — the 11 new SSL LVO implementations.
 *      Because they share a translation unit with bsdsocket.c, they can
 *      call those static helpers directly.
 *
 * Nothing in bsdsocket.c is modified.  The SSL stubs are entirely additive.
 *
 * bsd_gethostbyname and bsd_connect are wrapped here (not in bsdsocket.c): the
 * original functions are compiled under *_inner names via a #define rename before
 * the #include, and the public symbols are redefined below as thin wrappers that
 * apply the iBrowse AmiSSL-base patch (ib_patch_ssl_base).  socket() is unwrapped.
 *
 * Build: see Makefile.  The resulting bsdsocket.library has LIB_NEGSIZE_VAL
 * extended from 822 to 888, covering LVOs -828 through -888 for SSL.
 */

/* Rename gethostbyname and connect so we can wrap them: both apply the iBrowse
 * AmiSSL-base patch (ib_patch_ssl_base) to the caller's connection struct.
 * socket() needs no wrapper and is used directly from a314bsd's bsdsocket.c. */
#define bsd_gethostbyname bsd_gethostbyname_inner
#define bsd_connect       bsd_connect_inner

#include "bsdsocket.c"

#undef bsd_gethostbyname
#undef bsd_connect

#include "../include/ssl_proto.h"    /* BSDOP_* / BSDSSL_LVO_* for bsd_ssl_stubs.c */
#include <exec/tasks.h>              /* struct Task — for the iBrowse-only task-name gate */

/* iBrowse AmiSSL-base patch ------------------------------------------------
 * a4v = the protocol module's connection-context struct (iBrowse's http.protocol
 * keeps it in a4 across calls).  Layout (iBrowse 30.8 http.protocol/gemini.protocol):
 *   +0x8c  = SSL_CTX    (iBrowse fills this — a valid Pi ctx handle)
 *   +0x206 = AmiSSLBase (iBrowse leaves this 0 -> SSL_new does jsr -8784(a6=0) -> Guru)
 * We fill +0x206 with our amissl.library base so SSL_new runs with a valid a6.
 * Called from BOTH bsd_gethostbyname AND bsd_connect; connect() runs for EVERY new
 * TLS connection (gethostbyname is skipped when DNS is cached), so the connect path
 * also covers parallel/keep-alive connections.
 * Guard: a4 valid & even, ctx at +0x8c in the Pi handle range, base slot currently 0.
 * NOTE: the +0x206/+0x8c offsets are iBrowse-30.8-specific — the one deliberately
 * fragile, app-version-specific workaround in the shim.
 *
 * amissl.library is opened ONCE into g_amissl_base and reused for every patched
 * struct (avoids a per-connection OpenLibrary leak).  The single ref is intentionally
 * never closed: the base must stay valid as long as iBrowse holds the pointer we
 * wrote into its connection struct. */
static struct Library *g_amissl_base;

/* The +0x206 patch is an iBrowse-specific workaround and must NEVER touch any other
 * application's memory.  iBrowse runs its connections in a task whose name begins
 * with "IBrowse" (its network task is "IBrowseNetwork", confirmed empirically);
 * other browsers (AWeb, Amelinium, ...) use different task names and pass their own
 * AmiSSL base correctly, so they must be excluded.  Gating on the caller's task name
 * means the heuristic write can only ever land in iBrowse's own connection struct. */
static int caller_is_ibrowse(struct BsdBase *base)
{
    struct ExecBase *SysBase = base->SysBase;
    struct Task *me = FindTask(0L);
    STRPTR nm = me ? (STRPTR)me->tc_Node.ln_Name : (STRPTR)0;
    static const char want[] = "IBrowse";
    UWORD i;
    if (!nm)
        return 0;
    for (i = 0; want[i]; i++)
        if (nm[i] != (char)want[i])
            return 0;
    return 1;   /* task name begins with "IBrowse" */
}

static void ib_patch_ssl_base(ULONG a4v, struct BsdBase *base)
{
    volatile ULONG *ctxslot, *baseslot;
    ULONG ctx, curb;
    if (a4v <= 0x1000 || (a4v & 1))
        return;
    if (!caller_is_ibrowse(base))
        return;            /* iBrowse-only: never read or write another app's memory */
    ctxslot  = (volatile ULONG *)(a4v + 0x8c);
    baseslot = (volatile ULONG *)(a4v + 0x206);
    ctx  = *ctxslot;
    curb = *baseslot;
    /* ctx must be a valid Pi SSL_CTX handle (base 0x18000, step 0x10 — see
     * _HANDLE_CTX_BASE in bsdsocket.py) and the base slot must be uninitialised. */
    if (ctx >= 0x00018000UL && ctx < 0x000A0000UL && curb == 0) {
        struct ExecBase *SysBase = base->SysBase;
        if (!g_amissl_base)
            g_amissl_base = OpenLibrary((STRPTR)"amissl.library", 0);
        if (g_amissl_base)
            *baseslot = (ULONG)g_amissl_base;   /* http.protocol's a6 for SSL_new */
    }
}

struct hostent *bsd_gethostbyname(STRPTR name __asm("a0"),
                                  struct BsdBase *base __asm("a6"))
{
    struct hostent *hp;
    ULONG           a4v;

    /* Capture the caller's a4 (its per-connection context struct) BEFORE the inner
     * call can clobber it, then patch the AmiSSL-base slot once DNS succeeds. */
    __asm volatile ("move.l %%a4,%0" : "=r"(a4v));

    hp = bsd_gethostbyname_inner(name, base);
    if (!hp)
        return NULL;

    ib_patch_ssl_base(a4v, base);
    return hp;
}

/* bsd_connect wrapper: patch the iBrowse AmiSSL-base slot for EVERY new TLS
 * connection (covers parallel/keep-alive connections that reuse cached DNS).
 *   d0 = fd, a0 = sockaddr*, d1 = namelen, a6 = BsdBase (AmiTCP LVO -54) */
LONG bsd_connect(LONG fd        __asm("d0"),
                 APTR sa        __asm("a0"),
                 LONG namelen   __asm("d1"),
                 struct BsdBase *base __asm("a6"))
{
    ULONG a4v;

    /* Capture the caller's a4 (its connection struct) and patch the AmiSSL-base slot. */
    __asm volatile ("move.l %%a4,%0" : "=r"(a4v));
    ib_patch_ssl_base(a4v, base);

    return bsd_connect_inner(fd, (APTR)sa, namelen, base);
}

/* SSL stubs — compiled in the same translation unit. */
#include "bsd_ssl_stubs.c"
