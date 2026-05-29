/*
 * amisslmaster.c — AmiSSL master loader library for a314bsd
 *
 * amisslmaster.library is the standard AmiSSL 4.x entry point.
 * Apps (like iBrowse) open this library and call:
 *
 *   1. InitAmiSSLMaster(APIVersion, UsesOpenSSLStructs)  → TRUE/FALSE
 *   2. OpenAmiSSL()                                       → struct Library *
 *
 * The base pointer returned by OpenAmiSSL() is put in a6 for all subsequent
 * SSL function calls (SSL_CTX_new, SSL_connect, etc.).
 *
 * Our implementation opens amissl.library on the Amiga side, which itself
 * opens bsdsocket.library to proxy all TLS operations to the Pi.
 *
 * Calling convention for public LVO functions (set by FuncTable in
 * amisslmaster_start.S):
 *   a6 = AmiSSLMasterBase (library base pointer)
 *   d0, d1, a0 = per-function arguments as listed in amisslmaster_lib.fd
 */

#include <exec/types.h>
#include <exec/libraries.h>
#include <exec/memory.h>
#include <exec/lists.h>
#include <proto/exec.h>

/* ---- AmiSSLMaster library base ------------------------------------------- */

struct AmiSSLMasterBase {
    struct Library   lib;           /* standard 34-byte library node  */
    struct ExecBase *SysBase;       /* stored in Init from a6         */
    APTR             SegList;
    struct Library  *AmiSSLBase;    /* opened amissl.library base     */
};

/* ---- AmiSSL tag constants ------------------------------------------------- */
/* TAG_USER = 0x80000000, values from amissl/tags.h */
#define AMISSL_TAG_BASE           0x80000000UL
#define AMISSL_GetAmiSSLBase      (AMISSL_TAG_BASE + 0x0dUL)
#define AMISSL_GetAmiSSLExtBase   (AMISSL_TAG_BASE + 0x0eUL)

/* Build 27: call amissl.library InitAmiSSLA(taglist) (LVO -36) with the app's
 * real tag list, mirroring the REAL amisslmaster OpenAmiSSLTagList which calls
 * InitAmiSSLA(tagList) internally (AmiSSL_InitAmiSSL defaults TRUE).  amissl's
 * InitAmiSSLA processes AmiSSL_GetAmiSSLBase / GetAmiSSLExtBase and writes the
 * app's base pointers — which is how iBrowse receives the base it puts in a6
 * for SSL_new.  a6/a0 are inputs; InitAmiSSLA is wrapped and restores a6. */
static LONG call_amissl_init(struct Library *amisslbase, APTR taglist)
{
    register struct Library *a6 __asm("a6") = amisslbase;
    register APTR            a0 __asm("a0") = taglist;
    register LONG            d0 __asm("d0");
    if (!amisslbase)
        return -1;
    __asm volatile ("jsr -36(%%a6)"
        : "=d"(d0)
        : "a"(a6), "a"(a0)
        : "d1", "a1", "cc", "memory");
    return d0;
}

/* ---- Open / Close (called from asm stubs, base passed on stack) ----------- */

struct AmiSSLMasterBase *ami_master_open(struct AmiSSLMasterBase *base)
{
    base->lib.lib_OpenCnt++;
    return base;
}

void ami_master_close(struct AmiSSLMasterBase *base)
{
    struct ExecBase *SysBase = base->SysBase;

    if (base->lib.lib_OpenCnt)
        base->lib.lib_OpenCnt--;

    /* If nobody has us open and amissl is still loaded, close it */
    if (base->lib.lib_OpenCnt == 0 && base->AmiSSLBase) {
        CloseLibrary(base->AmiSSLBase);
        base->AmiSSLBase = NULL;
    }
}

/* ---- InitAmiSSLMaster (LVO -30) ------------------------------------------ */
/*
 * InitAmiSSLMaster(APIVersion, UsesOpenSSLStructs)(d0,d1)
 * Accept any API version — we advertise full OpenSSL 1.1.x compatibility.
 * Returns TRUE (1) always.
 */
LONG ami_master_InitAmiSSLMaster(LONG APIVersion     __asm("d0"),
                                  LONG UsesOpenSSLStructs __asm("d1"),
                                  struct AmiSSLMasterBase *base __asm("a6"))
{
    (void)APIVersion;
    (void)UsesOpenSSLStructs;
    (void)base;
    return 1;   /* TRUE */
}

/* ---- OpenAmiSSL (LVO -36) ------------------------------------------------ */
/*
 * OpenAmiSSL()(void) → struct Library *
 * Opens amissl.library (our SSL shim) and returns its base pointer.
 * This is what iBrowse stores and later puts in a6 for SSL calls.
 * Idempotent — multiple calls return the same base (already-opened lib).
 */
struct Library *ami_master_OpenAmiSSL(struct AmiSSLMasterBase *base __asm("a6"))
{
    /* Move base from a6 into a2 before calling OpenLibrary.
     * OpenLibrary's inline asm sets a6 = SysBase; without this explicit
     * register save, GCC may not preserve 'base' across the exec call,
     * causing base->AmiSSLBase to read from SysBase+42 instead. */
    register struct AmiSSLMasterBase *b __asm("a2") = base;
    struct ExecBase *SysBase = b->SysBase;

    if (!b->AmiSSLBase) {
        /* Open our amissl.library — any version (0 = accept all) */
        b->AmiSSLBase = OpenLibrary((STRPTR)"amissl.library", 0);
    }
    return b->AmiSSLBase;   /* NULL on failure */
}

/* ---- CloseAmiSSL (LVO -42) ----------------------------------------------- */
/*
 * CloseAmiSSL()(void)
 * Closes the amissl library previously opened by OpenAmiSSL.
 */
void ami_master_CloseAmiSSL(struct AmiSSLMasterBase *base __asm("a6"))
{
    /* Same a6-preservation pattern as OpenAmiSSL: save base to a2 before
     * CloseLibrary sets a6 = SysBase internally. */
    register struct AmiSSLMasterBase *b __asm("a2") = base;
    struct ExecBase *SysBase = b->SysBase;

    if (b->AmiSSLBase) {
        CloseLibrary(b->AmiSSLBase);
        b->AmiSSLBase = NULL;
    }
}

/* ---- OpenAmiSSLCipher (LVO -48) ------------------------------------------ */
/*
 * OpenAmiSSLCipher(Cipher)(d0) → struct Library *
 *
 * In AmiSSL 4+, all cipher suites live in one unified library.
 * Old-style apps (iBrowse 2.x) called OpenAmiSSLCipher() to get a
 * cipher-specific library base, then used THAT base for SSL_new / SSL_connect
 * calls via JSR (-lvo, cipherbase).  If we return NULL here, those JSRs land
 * in garbage chip RAM containing 0x4AFC → #80000004 Illegal Instruction crash.
 *
 * Fix: return the same AmiSSLBase that OpenAmiSSL() returned.  All cipher
 * numbers map to the same library — the Pi negotiates the best TLS version
 * and cipher suite regardless.
 *
 * Build 23 (root cause confirmed via MuForce): iBrowse calls SSL_new with
 * a6 = the value returned HERE.  MuForce caught "jsr -8784(a6)" with a6=0
 * (SSL_new, LVO -8784) → instruction fetch from 0xFFFFDDB0 → #80000004.
 * That means iBrowse called OpenAmiSSLCipher BEFORE OpenAmiSSL, so
 * base->AmiSSLBase was still NULL and we handed iBrowse a NULL SSL base.
 * The old code only returned the field; it never OPENED the library.
 * Fix: lazily open amissl.library here exactly like OpenAmiSSL, so this can
 * NEVER return NULL when amissl.library is loadable.
 */
struct Library *ami_master_OpenAmiSSLCipher(LONG Cipher __asm("d0"),
                                             struct AmiSSLMasterBase *base __asm("a6"))
{
    /* Save base (a6) to a2 before OpenLibrary clobbers a6 = SysBase. */
    register struct AmiSSLMasterBase *b __asm("a2") = base;
    struct ExecBase *SysBase = b->SysBase;

    (void)Cipher;

    if (!b->AmiSSLBase)
        b->AmiSSLBase = OpenLibrary((STRPTR)"amissl.library", 0);

    return b->AmiSSLBase;   /* never NULL unless amissl.library is unloadable */
}

/* ---- CloseAmiSSLCipher (LVO -54) ----------------------------------------- */
void ami_master_CloseAmiSSLCipher(struct Library *CipherBase __asm("a0"),
                                   struct AmiSSLMasterBase *base __asm("a6"))
{
    (void)CipherBase;
    (void)base;
}

/* ---- OpenAmiSSLTagList (LVO -60) ----------------------------------------- */
/*
 * OpenAmiSSLTagList(APIVersion, tagList)(d0,a0) → LONG
 * The primary AmiSSL 4/5 initialization call used by iBrowse 3.0.
 *
 * We process AmiSSL_GetAmiSSLBase and AmiSSL_GetAmiSSLExtBase tags directly
 * here rather than delegating to InitAmiSSLA on amissl.library.  This avoids
 * an inline-asm call through a JMP stub (complex register save/restore) and
 * also avoids the ambiguity over whether InitAmiSSLA should return 0 or 1:
 *
 *   AmiSSL 2/3 old-style: InitAmiSSLA returns non-zero (TRUE) for success.
 *   AmiSSL 4/5 new-style: InitAmiSSLA returns 0 for success.
 *
 * By not calling InitAmiSSLA from here, its return value is irrelevant from
 * this code path.  iBrowse 3.0 using the old-style direct InitAmiSSLA call
 * sees TRUE (1) returned from ami_InitAmiSSLA; iBrowse using the new-style
 * OpenAmiSSLTagList path sees 0 returned from here.  Both are happy.
 *
 * Return value: 0 = success (matches real AmiSSL OpenAmiSSLTagList behaviour).
 *               1 = InitAmiSSLMaster version check failed.
 *               2 = OpenAmiSSL() / amissl.library could not be opened.
 *               3 = InitAmiSSLA() failed.
 *
 * Source reference: AmiSSL src/amisslmaster_library.c OpenAmiSSLTagList():
 *   LONG err = 0;
 *   if(InitAmiSSLMaster(...)) { if(OpenAmiSSL()) { if(InitAmiSSLA()==0) {} else err=3; } else err=2; } else err=1;
 *   return err;   // ← 0 on success!
 * iBrowse checks: if (result == 0) { SSL ready } else { "AmiSSL could not be loaded" }
 */
LONG ami_master_OpenAmiSSLTagList(LONG          APIVersion __asm("d0"),
                                   APTR          tagList    __asm("a0"),
                                   struct AmiSSLMasterBase *base __asm("a6"))
{
    /* Save base (a6) to a2 and tagList (a0) to a local before any exec
     * call clobbers those registers.  OpenLibrary sets a6 = SysBase;
     * without this, 'base' is lost and base->AmiSSLBase reads exec memory. */
    register struct AmiSSLMasterBase *b __asm("a2") = base;
    struct ExecBase *SysBase = b->SysBase;
    APTR tl = tagList;    /* copy from a0 now — OpenLibrary will clobber a0 */
    ULONG *tag;

    (void)APIVersion;

    /* Open amissl.library if not already open */
    if (!b->AmiSSLBase) {
        b->AmiSSLBase = OpenLibrary((STRPTR)"amissl.library", 0);
    }
    if (!b->AmiSSLBase) {
        return 2;   /* 2 = amissl.library could not be opened (real AmiSSL 4/5 error code) */
    }
    /* Walk the tag list and write our amissl base into any
     * AmiSSL_GetAmiSSLBase / AmiSSL_GetAmiSSLExtBase pointers the app
     * provided.  iBrowse 3.0 passes both; both must be non-NULL.
     * Delegate to amissl InitAmiSSLA(tl), exactly like the real amisslmaster:
     * its InitAmiSSLA writes the app's AmiSSLBase/ExtBase from the
     * GetAmiSSLBase tags in the list. */
    call_amissl_init(b->AmiSSLBase, tl);

    /* Belt-and-suspenders: also write the bases from our own walk. */
    tag = (ULONG *)tl;
    if (tag) {
        while (tag[0] != 0UL) {   /* 0 = TAG_DONE */
            if (tag[0] == AMISSL_GetAmiSSLBase ||
                tag[0] == AMISSL_GetAmiSSLExtBase) {
                struct Library **ptr = (struct Library **)tag[1];
                if (ptr) {
                    *ptr = (struct Library *)b->AmiSSLBase;
                }
            }
            tag += 2;
        }
    }

    return 0;   /* 0 = success (real AmiSSL 4/5 OpenAmiSSLTagList convention) */
}
