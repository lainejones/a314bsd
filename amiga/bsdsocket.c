/*
 * bsdsocket.c - a314BSD bsdsocket.library
 *
 * Each OpenLibrary() call connects a new A314 stream to the "bsdsocket"
 * service running on the Pi.  All socket operations are synchronous
 * request/response over that stream.
 *
 * Wire protocol (all multi-byte fields big-endian, native on m68k):
 *   Request:  opcode(1) seq(1) arglen(2) args[arglen]
 *   Response: seq(1) result(4) datalen(2) data[datalen]
 *   result >= 0: success / return value
 *   result <  0: -errno (BSD/AmiTCP errno values)
 */

#include <exec/types.h>
#include <exec/execbase.h>
#include <exec/libraries.h>
#include <exec/lists.h>
#include <exec/memory.h>
#include <exec/io.h>
#include <exec/ports.h>
#include <exec/tasks.h>

#include <proto/exec.h>

#include <netinclude/sys/socket.h>
#include <netinclude/sys/select.h>
#include <netinclude/netinet/in.h>
#include <netinclude/netdb.h>

#include <a314.h>
#include <bsd_proto.h>

/* ---- Library base -------------------------------------------------------- */

struct BsdBase {
    struct Library   lib;
    struct ExecBase *SysBase;
    APTR             SegList;
    struct MinList   sessions;
};

/* ---- Per-opener session -------------------------------------------------- */

/*
 * A314 ring-buffer limit: each PKT_DATA payload must fit in the 256-byte ring
 * buffer less a 3-byte header, and the Amiga device rejects writes with
 * len + 3 > 255 — so the hard ceiling is 252 bytes per A314_READ or A314_WRITE.
 *
 * We derive two constants:
 *   A314_MAX_PAYLOAD  252  — absolute hardware limit per message
 *   BSD_MAX_DATA_RECV 245  — max data per recv response  (252 − 7 RSP hdr)
 *   BSD_MAX_DATA_SEND 242  — max data per send request   (252 − 4 REQ hdr − 6 args)
 *
 * SESSION_IO_SIZE only needs to cover one message at a time.
 */
#define A314_MAX_PAYLOAD    252
#define BSD_MAX_DATA_RECV   245   /* A314_MAX_PAYLOAD - BSD_RSP_HDR_SIZE(7) */
#define BSD_MAX_DATA_SEND   242   /* A314_MAX_PAYLOAD - BSD_REQ_HDR_SIZE(4) - send_args(6) */
#define SESSION_IO_SIZE     256   /* one ring-buffer worth */

struct BsdSession {
    struct MinNode         node;
    struct Task           *task;

    struct MsgPort        *port;
    struct A314_IORequest *ior;

    LONG                   errno_val;
    UBYTE                  seq;

    /* protoent result buffer — filled by getprotobyname/getprotobynumber */
    struct protoent        pent;
    BYTE                   pent_name[16];
    APTR                   pent_aliases[1]; /* { NULL } */

    /* hostent result buffers — reused across gethostbyname calls */
    struct hostent         hent;
    BYTE                   hname[256];
    ULONG                  haddr;          /* first address, net-byte-order */
    APTR                   haddr_list[2];  /* { &haddr, NULL } */
    APTR                   haliases[1];    /* { NULL } */

    /* inet_ntoa result buffer */
    BYTE                   ntoa_buf[20];

    /* servent result buffers — reused across getservby* calls */
    struct servent         sent;
    BYTE                   sent_name[64];   /* service name  */
    BYTE                   sent_proto[16];  /* protocol name */
    APTR                   sent_aliases[1]; /* { NULL }      */

    /* Unified request/response I/O buffer */
    UBYTE                  io_buf[SESSION_IO_SIZE];
};

/* ---- Exec shorthand ------------------------------------------------------ */
/* SysBase must be declared as a local 'struct ExecBase *SysBase' in each
 * function so that the proto/exec.h inline macros pick it up. */

/* ---- Low-level helpers --------------------------------------------------- */

static void w16(UBYTE *p, UWORD v)
{
    p[0] = (UBYTE)(v >> 8);
    p[1] = (UBYTE)(v & 0xFF);
}

static void w32(UBYTE *p, ULONG v)
{
    p[0] = (UBYTE)(v >> 24);
    p[1] = (UBYTE)(v >> 16);
    p[2] = (UBYTE)(v >>  8);
    p[3] = (UBYTE)(v & 0xFF);
}

/* Fill the 4-byte request header at io_buf[0..3].
 * noinline: prevents -O2 from reordering or eliminating the opcode write. */
static __attribute__((noinline)) void fill_hdr(struct BsdSession *sess,
                                               UBYTE opcode, UWORD arglen)
{
    sess->io_buf[0] = opcode;
    sess->io_buf[1] = sess->seq++;
    sess->io_buf[2] = (UBYTE)(arglen >> 8);
    sess->io_buf[3] = (UBYTE)(arglen & 0xFF);
}

/* ---- RPC: write request from io_buf, read response into io_buf ----------- */
/*
 * Caller must have filled io_buf[0 .. req_total-1] with the complete
 * request frame (header + args).  On return io_buf holds the response.
 * Returns result field (>=0 success, <0 -errno); sets sess->errno_val.
 */
static LONG do_rpc(struct BsdSession *sess, struct ExecBase *SysBase,
                   UWORD req_total)
{
    struct BsdRspHdr *rsp;
    LONG r;

    /* Write request */
    sess->ior->a314_Request.io_Command = A314_WRITE;
    sess->ior->a314_Buffer             = (STRPTR)sess->io_buf;
    sess->ior->a314_Length             = (WORD)req_total;
    if (DoIO((struct IORequest *)sess->ior) != A314_WRITE_OK) {
        sess->errno_val = 5; /* EIO: A314 WRITE failed (EOS-sent or RESET) */
        return -5;
    }

    /* Read response (overwrites io_buf — request is already sent) */
    sess->ior->a314_Request.io_Command = A314_READ;
    sess->ior->a314_Buffer             = (STRPTR)sess->io_buf;
    sess->ior->a314_Length             = (WORD)SESSION_IO_SIZE;
    r = DoIO((struct IORequest *)sess->ior);
    if (r != A314_READ_OK || sess->ior->a314_Length < BSD_RSP_HDR_SIZE) {
        sess->errno_val = 6; /* ENXIO: A314 READ failed (EOS or RESET from Pi) */
        return -6;
    }

    rsp = (struct BsdRspHdr *)sess->io_buf;
    r   = rsp->result;   /* packed LONG, big-endian = native on m68k */
    sess->errno_val = (r < 0) ? -r : 0;
    return r;
}

/* Normalize do_rpc() to standard BSD return conventions.
 * errno is already set by do_rpc(); just clamp negative to -1.
 *   RPC_RET  — for calls that return fd / byte-count on success
 *   RPC_ZERO — for calls that return 0 on success
 *
 * IMPORTANT: implemented as static inline functions, NOT macros.
 * A macro form like ((r)<0?-1:(r)) would evaluate the argument TWICE
 * when r >= 0, causing do_rpc() to be called a second time with stale
 * io_buf contents — that's the "opcode=0 mystery packet" bug. */
static __inline LONG rpc_ret(LONG r)  { return r < 0 ? -1L : r;  }
static __inline LONG rpc_zero(LONG r) { return r < 0 ? -1L : 0L; }
#define RPC_RET(r)  rpc_ret(r)
#define RPC_ZERO(r) rpc_zero(r)

/* ---- Session lookup ------------------------------------------------------ */

static struct BsdSession *find_session(struct BsdBase *base)
{
    struct ExecBase   *SysBase = base->SysBase;
    struct Task       *me      = FindTask(NULL);
    struct BsdSession *s;

    for (s = (struct BsdSession *)base->sessions.mlh_Head;
         s->node.mln_Succ != NULL;
         s = (struct BsdSession *)s->node.mln_Succ)
    {
        if (s->task == me)
            return s;
    }
    return NULL;
}

/* ---- Orphan cleanup ------------------------------------------------------ */
/*
 * When an application crashes without calling CloseLibrary, our Close
 * function is never called, leaving a "zombie" BsdSession in the list
 * with its a314 device still open.  The pending A314_READ DoIO for that
 * stream keeps the ring buffer blocked, so the next A314_CONNECT from any
 * task fails immediately (nothing reaches the Pi).
 *
 * Called at the top of bsd_open: scan the sessions list, check exec's
 * task ready/wait queues, and close any session whose owning task no
 * longer exists.
 *
 * The tricky part: DoIO is safe only when the IORequest's reply port
 * belongs to the calling task (otherwise Signal() would target the dead
 * task's stack).  We solve this by temporarily replacing the reply port
 * with a freshly-created port owned by the current task before issuing
 * A314_EOS + CloseDevice.  The original orphaned port's signal bit was
 * allocated in the dead task; that task's memory is gone, so we skip
 * FreeSignal and free the port memory directly with FreeMem.
 */
static void cleanup_orphaned_sessions(struct BsdBase *base,
                                      struct ExecBase *SysBase)
{
    struct Task       *me = FindTask(NULL);
    struct BsdSession *s, *next;
    struct Node       *n;
    BOOL               alive;

    s = (struct BsdSession *)base->sessions.mlh_Head;
    while (s->node.mln_Succ != NULL)
    {
        next = (struct BsdSession *)s->node.mln_Succ;

        if (s->task == me) { s = next; continue; } /* current task: skip */

        /* Check exec task lists — must Forbid while scanning. */
        Forbid();
        alive = FALSE;
        for (n = SysBase->TaskReady.lh_Head; !alive && n->ln_Succ; n = n->ln_Succ)
            if ((struct Task *)n == s->task) alive = TRUE;
        for (n = SysBase->TaskWait.lh_Head; !alive && n->ln_Succ; n = n->ln_Succ)
            if ((struct Task *)n == s->task) alive = TRUE;
        Permit();

        if (!alive)
        {
            struct MsgPort *tmp;

            Remove((struct Node *)&s->node);

            /* Replace orphaned reply port so DoIO signals the current task. */
            tmp = CreateMsgPort();
            if (tmp)
            {
                s->ior->a314_Request.io_Message.mn_ReplyPort = tmp;
                s->ior->a314_Request.io_Command = A314_EOS;
                DoIO((struct IORequest *)s->ior);  /* tell Pi stream is done */
                DeleteMsgPort(tmp);
            }
            CloseDevice((struct IORequest *)s->ior);
            DeleteIORequest((struct IORequest *)s->ior);

            /* The original port's AllocSignal was charged to the dead task.
             * Calling DeleteMsgPort would FreeSignal into freed memory.
             * Skip straight to FreeMem — the signal bit is already gone. */
            FreeMem(s->port, sizeof(struct MsgPort));

            FreeVec(s);
            base->lib.lib_OpenCnt--;
        }

        s = next;
    }
}

/* ---- Open/Close ---------------------------------------------------------- */

struct BsdBase *bsd_open(struct BsdBase *base)
{
    struct ExecBase       *SysBase = base->SysBase;
    struct BsdSession     *sess;
    struct MsgPort        *port;
    struct A314_IORequest *ior;
    ULONG                  attempt;

    /* Clean up sessions left behind by tasks that crashed without calling
     * CloseLibrary — their pending A314_READ blocks the ring buffer. */
    cleanup_orphaned_sessions(base, SysBase);

    sess = (struct BsdSession *)AllocVec(sizeof(struct BsdSession),
                                         MEMF_PUBLIC | MEMF_CLEAR);
    if (!sess) return NULL;

    /*
     * Retry loop for OpenDevice + A314_CONNECT.
     *
     * After a rapid CloseDevice/OpenDevice cycle the a314 device task may
     * not have had a scheduling slot to finish its internal teardown.  Each
     * retry recreates the port and IORequest (cheap exec calls that yield
     * to other tasks) giving the device time to settle.  Three attempts
     * covers any transient race; if all fail we return NULL.
     */
    port = NULL;
    ior  = NULL;
    for (attempt = 0; attempt < 3; attempt++)
    {
        port = CreateMsgPort();
        if (!port) { FreeVec(sess); return NULL; }

        ior = (struct A314_IORequest *)CreateIORequest(port,
                                        sizeof(struct A314_IORequest));
        if (!ior) { DeleteMsgPort(port); FreeVec(sess); return NULL; }

        if (OpenDevice((STRPTR)A314_NAME, 0, (struct IORequest *)ior, 0) != 0) {
            DeleteIORequest((struct IORequest *)ior);
            DeleteMsgPort(port);
            port = NULL; ior = NULL;
            continue;
        }

        /* Connect to bsdsocket service on the Pi */
        ior->a314_Socket             = (ULONG)sess;
        ior->a314_Buffer             = (STRPTR)"bsdsocket";
        ior->a314_Length             = 9;
        ior->a314_Request.io_Command = A314_CONNECT;

        if (DoIO((struct IORequest *)ior) == A314_CONNECT_OK)
            break; /* connected */

        CloseDevice((struct IORequest *)ior);
        DeleteIORequest((struct IORequest *)ior);
        DeleteMsgPort(port);
        port = NULL; ior = NULL;
    }

    if (!port) { FreeVec(sess); return NULL; } /* all 3 attempts failed */

    /* Wire up hostent in the session (pointers never change) */
    sess->haddr_list[0]   = (APTR)&sess->haddr;
    sess->haddr_list[1]   = NULL;
    sess->haliases[0]     = NULL;
    sess->hent.h_name     = sess->hname;
    sess->hent.h_aliases  = (char **)sess->haliases;
    sess->hent.h_addrtype = AF_INET;
    sess->hent.h_length   = 4;
    sess->hent.h_addr_list= (char **)sess->haddr_list;

    /* Wire up servent in the session (pointers never change) */
    sess->sent_aliases[0] = NULL;
    sess->sent.s_name     = sess->sent_name;
    sess->sent.s_aliases  = (char **)sess->sent_aliases;
    sess->sent.s_proto    = sess->sent_proto;

    /* Wire up protoent in the session (pointers never change) */
    sess->pent_aliases[0] = NULL;
    sess->pent.p_name     = sess->pent_name;
    sess->pent.p_aliases  = (char **)sess->pent_aliases;

    sess->task = FindTask(NULL);
    sess->port = port;
    sess->ior  = ior;

    AddTail((struct List *)&base->sessions, (struct Node *)&sess->node);
    base->lib.lib_OpenCnt++;
    return base;
}

void bsd_close_lib(struct BsdBase *base)
{
    struct ExecBase   *SysBase = base->SysBase;
    struct BsdSession *sess    = find_session(base);

    if (sess) {
        Remove((struct Node *)&sess->node);

        sess->ior->a314_Request.io_Command = A314_EOS;
        DoIO((struct IORequest *)sess->ior);

        CloseDevice((struct IORequest *)sess->ior);
        DeleteIORequest((struct IORequest *)sess->ior);
        DeleteMsgPort(sess->port);
        FreeVec(sess);
    }
    base->lib.lib_OpenCnt--;
}

/* ---- errno --------------------------------------------------------------- */

LONG bsd_errno(struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    return sess ? sess->errno_val : 0;
}

void bsd_seterrnoptr(APTR a0 __asm("a0"), LONG d0 __asm("d0"),
                     struct BsdBase *base __asm("a6"))
{
    /* Optional: store caller's errno pointer.  Not implemented. */
    (void)a0; (void)d0; (void)base;
}

/* ---- socket() ------------------------------------------------------------ */

LONG bsd_socket(LONG domain __asm("d0"), LONG type __asm("d1"),
                LONG proto  __asm("d2"), struct BsdBase *base __asm("a6"))
{
    struct ExecBase   *SysBase = base->SysBase;
    struct BsdSession *sess    = find_session(base);
    (void)SysBase;
    if (!sess) { return -1; }

    /* args: domain(2) type(2) protocol(2) */
    fill_hdr(sess, BSDOP_SOCKET, 6);
    w16(&sess->io_buf[4], (UWORD)domain);
    w16(&sess->io_buf[6], (UWORD)type);
    w16(&sess->io_buf[8], (UWORD)proto);
    return RPC_RET(do_rpc(sess, base->SysBase, 10));
}

/* ---- bind() -------------------------------------------------------------- */

LONG bsd_bind(LONG fd __asm("d0"), APTR sa __asm("a0"), LONG addrlen __asm("d1"),
              struct BsdBase *base __asm("a6"))
{
    struct ExecBase   *SysBase = base->SysBase;
    struct BsdSession *sess    = find_session(base);
    UBYTE *p, *src;
    UWORD  i, alen;
    (void)SysBase;
    if (!sess) return -1;
    if (addrlen < 0 || addrlen > 64) addrlen = 16;

    alen = 3 + (UWORD)addrlen; /* fd(2) addrlen(1) addr[] */
    fill_hdr(sess, BSDOP_BIND, alen);
    p = &sess->io_buf[4];
    w16(p, (UWORD)fd); p += 2;
    *p++ = (UBYTE)addrlen;
    src = (UBYTE *)sa;
    for (i = 0; i < (UWORD)addrlen; i++) *p++ = src[i];
    return RPC_ZERO(do_rpc(sess, base->SysBase, 4 + alen));
}

/* ---- listen() ------------------------------------------------------------ */

LONG bsd_listen(LONG fd __asm("d0"), LONG backlog __asm("d1"),
                struct BsdBase *base __asm("a6"))
{
    struct ExecBase   *SysBase = base->SysBase;
    struct BsdSession *sess    = find_session(base);
    (void)SysBase;
    if (!sess) return -1;

    fill_hdr(sess, BSDOP_LISTEN, 4);
    w16(&sess->io_buf[4], (UWORD)fd);
    w16(&sess->io_buf[6], (UWORD)backlog);
    return RPC_ZERO(do_rpc(sess, base->SysBase, 8));
}

/* ---- accept() ------------------------------------------------------------ */

LONG bsd_accept(LONG fd __asm("d0"), APTR sa __asm("a0"), LONG *addrlen __asm("a1"),
                struct BsdBase *base __asm("a6"))
{
    struct ExecBase   *SysBase = base->SysBase;
    struct BsdSession *sess    = find_session(base);
    struct BsdRspHdr  *rsp;
    LONG   r;
    UBYTE *data;
    UBYTE  alen;
    UWORD  i;
    (void)SysBase;
    if (!sess) return -1;

    fill_hdr(sess, BSDOP_ACCEPT, 2);
    w16(&sess->io_buf[4], (UWORD)fd);
    r = do_rpc(sess, base->SysBase, 6);
    if (r < 0 || !sa || !addrlen) return r;

    rsp  = (struct BsdRspHdr *)sess->io_buf;
    data = sess->io_buf + BSD_RSP_HDR_SIZE;
    if (rsp->datalen < 1) return r;

    alen = data[0]; /* first byte = addrlen */
    if (addrlen) *addrlen = (LONG)alen;
    if (sa && alen > 0) {
        UBYTE *dst = (UBYTE *)sa;
        for (i = 0; i < alen && i < 64; i++) dst[i] = data[1 + i];
    }
    return r;
}

/* ---- connect() ----------------------------------------------------------- */

LONG bsd_connect(LONG fd __asm("d0"), APTR sa __asm("a0"), LONG addrlen __asm("d1"),
                 struct BsdBase *base __asm("a6"))
{
    struct ExecBase   *SysBase = base->SysBase;
    struct BsdSession *sess    = find_session(base);
    UBYTE *p, *src;
    UWORD  i, alen;
    (void)SysBase;
    if (!sess) return -1;
    if (addrlen < 0 || addrlen > 64) addrlen = 16;

    alen = 3 + (UWORD)addrlen;
    fill_hdr(sess, BSDOP_CONNECT, alen);
    p = &sess->io_buf[4];
    w16(p, (UWORD)fd); p += 2;
    *p++ = (UBYTE)addrlen;
    src = (UBYTE *)sa;
    for (i = 0; i < (UWORD)addrlen; i++) *p++ = src[i];
    return RPC_ZERO(do_rpc(sess, base->SysBase, 4 + alen));
}

/* ---- send() -------------------------------------------------------------- */

LONG bsd_send(LONG fd __asm("d0"), APTR buf __asm("a0"), LONG len __asm("d1"),
              LONG flags __asm("d2"), struct BsdBase *base __asm("a6"))
{
    struct ExecBase   *SysBase = base->SysBase;
    struct BsdSession *sess    = find_session(base);
    UBYTE *src;
    LONG   total, r;
    UWORD  ulen, alen, i;
    (void)SysBase;
    if (!sess || len <= 0) return (len == 0) ? 0 : -1;

    /*
     * Loop to handle HTTP requests (and any payload) larger than
     * BSD_MAX_DATA_SEND (242 bytes) per A314 message.  Without this loop,
     * a request larger than 242 bytes is truncated: bsd_send returns 242,
     * the application thinks all data was sent, the server receives an
     * incomplete request (no trailing \r\n\r\n), waits, then closes.
     *
     * This mirrors the recv loop in bsd_recv which exists for the same
     * reason (smb2fs large reads).
     *
     * On error with no bytes yet → return error.
     * On error after partial data → return partial count (POSIX semantics).
     * If Pi returns fewer bytes than requested (non-blocking buffer full) →
     *   stop looping so the caller can react to the short send.
     */
    src   = (UBYTE *)buf;
    total = 0;

    do {
        ulen = ((len - total) > (LONG)BSD_MAX_DATA_SEND)
               ? BSD_MAX_DATA_SEND
               : (UWORD)(len - total);
        alen = 6 + ulen; /* fd(2) flags(2) datalen(2) data[] */

        fill_hdr(sess, BSDOP_SEND, alen);
        w16(&sess->io_buf[4], (UWORD)fd);
        w16(&sess->io_buf[6], (UWORD)flags);
        w16(&sess->io_buf[8], ulen);
        for (i = 0; i < ulen; i++) sess->io_buf[10 + i] = src[total + i];

        r = do_rpc(sess, base->SysBase, 4 + alen);
        if (r < 0) return (total > 0) ? total : -1;

        total += r;

        /* If Pi forwarded fewer bytes than we asked (non-blocking socket
         * buffer full, or short write), stop here so the caller sees the
         * partial count and can retry the rest. */
        if (r < (LONG)ulen) break;

    } while (total < len);

    return total;
}

/* ---- recv() -------------------------------------------------------------- */
/*
 * Loop until all 'len' bytes have been received (stream semantics).
 *
 * Each A314 RPC is capped at BSD_MAX_DATA_RECV (245) bytes.  Applications
 * like smb2fs/libsmb2 issue large recv() calls (e.g. recv(fd,buf,65536,0))
 * and rely on getting exactly 'len' bytes back from a blocking socket — they
 * do NOT loop on partial reads.  Without this loop the Amiga receives only
 * 245 bytes of what it thinks is a complete SMB2 READ payload, interprets
 * garbage as protocol fields, and crashes.
 *
 * Termination: EOF (r == 0) or error (r < 0).
 *   - Error with no bytes yet → return the error.
 *   - Error after partial data → return the partial count so the caller can
 *     detect the short-read on its next call (matching POSIX stream semantics).
 */
LONG bsd_recv(LONG fd __asm("d0"), APTR buf __asm("a0"), LONG len __asm("d1"),
              LONG flags __asm("d2"), struct BsdBase *base __asm("a6"))
{
    struct ExecBase   *SysBase = base->SysBase;
    struct BsdSession *sess    = find_session(base);
    struct BsdRspHdr  *rsp;
    LONG   total, r;
    UWORD  want, n, i;
    UBYTE *dst, *src;
    (void)SysBase;
    if (!sess || len <= 0) return (len == 0) ? 0 : -1;

    dst   = (UBYTE *)buf;
    total = 0;

    do {
        want = ((len - total) > (LONG)BSD_MAX_DATA_RECV)
               ? BSD_MAX_DATA_RECV
               : (UWORD)(len - total);

        fill_hdr(sess, BSDOP_RECV, 6);
        w16(&sess->io_buf[4], (UWORD)fd);
        w16(&sess->io_buf[6], (UWORD)flags);
        w16(&sess->io_buf[8], want);

        r = do_rpc(sess, base->SysBase, 10);
        if (r < 0) return (total > 0) ? total : r;
        if (r == 0) break; /* EOF / connection closed */

        rsp = (struct BsdRspHdr *)sess->io_buf;
        n   = rsp->datalen;
        if ((LONG)n > len - total) n = (UWORD)(len - total);

        src = sess->io_buf + BSD_RSP_HDR_SIZE;
        for (i = 0; i < n; i++) dst[total + i] = src[i];
        total += (LONG)n;

        /* MSG_PEEK does not consume data from the socket buffer.
         * Every repeated call returns the same bytes from the start.
         * Loop only once so callers get a single consistent snapshot. */
        if (flags & MSG_PEEK) break;

        /* If Pi returned fewer bytes than requested and MSG_WAITALL is
         * not set, the TCP receive buffer is now drained.  Return the
         * partial count so callers (e.g. HTTP) are not forced to block
         * waiting for data that may not arrive for a long time. */
        if (n < want && !(flags & MSG_WAITALL)) break;

    } while (total < len);

    return total;
}

/* ---- sendto() ------------------------------------------------------------ */

LONG bsd_sendto(LONG fd __asm("d0"), APTR buf __asm("a0"), LONG len __asm("d1"),
                LONG flags __asm("d2"), APTR sa __asm("a1"), LONG addrlen __asm("d3"),
                struct BsdBase *base __asm("a6"))
{
    struct ExecBase   *SysBase = base->SysBase;
    struct BsdSession *sess    = find_session(base);
    UBYTE *p, *src;
    UWORD  ulen, alen, saddrlen, i;
    (void)SysBase;
    if (!sess || len <= 0) return -1;

    /* sendto request = 4 REQ hdr + fd(2)+flags(2)+alen(1)+addr[]+dlen(2)+data[]
     * = 4 + 4 + 1 + saddrlen + 2 + ulen = 11 + saddrlen + ulen ≤ 252
     * With saddrlen ≤ 16 (IPv4): ulen ≤ 252 - 11 - 16 = 225 */
    saddrlen = (addrlen < 0 || addrlen > 64) ? 16 : (UWORD)addrlen;
    { UWORD dmax = A314_MAX_PAYLOAD - 11 - saddrlen;
      ulen = (len > (LONG)dmax) ? dmax : (UWORD)len; }
    alen     = 4 + 1 + saddrlen + 2 + ulen; /* fd(2) flags(2) alen(1) addr[] dlen(2) data[] */

    fill_hdr(sess, BSDOP_SENDTO, alen);
    p = &sess->io_buf[4];
    w16(p, (UWORD)fd);    p += 2;
    w16(p, (UWORD)flags); p += 2;
    *p++ = (UBYTE)saddrlen;
    src = (UBYTE *)sa;
    for (i = 0; i < saddrlen; i++) *p++ = src[i];
    w16(p, ulen); p += 2;
    src = (UBYTE *)buf;
    for (i = 0; i < ulen; i++) *p++ = src[i];
    return RPC_RET(do_rpc(sess, base->SysBase, 4 + alen));
}

/* ---- recvfrom() ---------------------------------------------------------- */

LONG bsd_recvfrom(LONG fd __asm("d0"), APTR buf __asm("a0"), LONG len __asm("d1"),
                  LONG flags __asm("d2"), APTR sa __asm("a1"), LONG *addrlen __asm("a2"),
                  struct BsdBase *base __asm("a6"))
{
    struct ExecBase   *SysBase = base->SysBase;
    struct BsdSession *sess    = find_session(base);
    struct BsdRspHdr  *rsp;
    LONG   r;
    UWORD  n, i;
    UBYTE *data, *dst;
    (void)SysBase;
    if (!sess || len <= 0) return -1;

    /* recvfrom response = 7 RSP hdr + data + 1 addrlen + addr (≤16)
     * = 7 + data + 17 → data ≤ 252 - 7 - 17 = 228 */
    fill_hdr(sess, BSDOP_RECVFROM, 6);
    w16(&sess->io_buf[4], (UWORD)fd);
    w16(&sess->io_buf[6], (UWORD)flags);
    w16(&sess->io_buf[8], (len > 228) ? 228 : (UWORD)len);

    r = do_rpc(sess, base->SysBase, 10);
    if (r <= 0) return r;

    /* data = recv_bytes + addrlen(1) + addr[] */
    rsp  = (struct BsdRspHdr *)sess->io_buf;
    data = sess->io_buf + BSD_RSP_HDR_SIZE;
    n    = (UWORD)r;
    if (n > (UWORD)len) n = (UWORD)len;
    dst  = (UBYTE *)buf;
    for (i = 0; i < n; i++) dst[i] = data[i];

    if (sa && addrlen && rsp->datalen > n) {
        UBYTE alen2 = data[n];
        if (addrlen) *addrlen = alen2;
        if (sa) {
            UBYTE *s2 = (UBYTE *)sa;
            for (i = 0; i < alen2 && i < 64; i++) s2[i] = data[n + 1 + i];
        }
    }
    return (LONG)n;
}

/* ---- shutdown() ---------------------------------------------------------- */

LONG bsd_shutdown(LONG fd __asm("d0"), LONG how __asm("d1"),
                  struct BsdBase *base __asm("a6"))
{
    struct ExecBase   *SysBase = base->SysBase;
    struct BsdSession *sess    = find_session(base);
    (void)SysBase;
    if (!sess) return -1;

    fill_hdr(sess, BSDOP_SHUTDOWN, 4);
    w16(&sess->io_buf[4], (UWORD)fd);
    w16(&sess->io_buf[6], (UWORD)how);
    return RPC_ZERO(do_rpc(sess, base->SysBase, 8));
}

/* ---- setsockopt() -------------------------------------------------------- */

LONG bsd_setsockopt(LONG fd __asm("d0"), LONG level __asm("d1"), LONG optname __asm("d2"),
                    APTR optval __asm("a0"), LONG optlen __asm("d3"),
                    struct BsdBase *base __asm("a6"))
{
    struct ExecBase   *SysBase = base->SysBase;
    struct BsdSession *sess    = find_session(base);
    UBYTE *p, *src;
    UWORD  uoptlen, alen, i;
    (void)SysBase;
    if (!sess) return -1;

    uoptlen = (optlen < 0 || optlen > 64) ? 4 : (UWORD)optlen;
    alen    = 8 + uoptlen; /* fd(2) level(2) optname(2) optlen(2) optval[] */

    fill_hdr(sess, BSDOP_SETSOCKOPT, alen);
    p = &sess->io_buf[4];
    w16(p, (UWORD)fd);      p += 2;
    w16(p, (UWORD)level);   p += 2;
    w16(p, (UWORD)optname); p += 2;
    w16(p, uoptlen);        p += 2;
    src = (UBYTE *)optval;
    for (i = 0; i < uoptlen; i++) *p++ = src[i];
    return RPC_ZERO(do_rpc(sess, base->SysBase, 4 + alen));
}

/* ---- getsockopt() -------------------------------------------------------- */

LONG bsd_getsockopt(LONG fd __asm("d0"), LONG level __asm("d1"), LONG optname __asm("d2"),
                    APTR optval __asm("a0"), LONG *optlen __asm("a1"),
                    struct BsdBase *base __asm("a6"))
{
    struct ExecBase   *SysBase = base->SysBase;
    struct BsdSession *sess    = find_session(base);
    struct BsdRspHdr  *rsp;
    LONG   r;
    UBYTE *data, *dst;
    UWORD  n, i;
    (void)SysBase;
    if (!sess) return -1;

    fill_hdr(sess, BSDOP_GETSOCKOPT, 6);
    w16(&sess->io_buf[4], (UWORD)fd);
    w16(&sess->io_buf[6], (UWORD)level);
    w16(&sess->io_buf[8], (UWORD)optname);

    r = do_rpc(sess, base->SysBase, 10);
    if (r < 0 || !optval || !optlen) return r;

    /* data = optlen(2) optval[] */
    rsp  = (struct BsdRspHdr *)sess->io_buf;
    data = sess->io_buf + BSD_RSP_HDR_SIZE;
    if (rsp->datalen < 2) return r;

    n = ((UWORD)data[0] << 8) | data[1];
    if (optlen) *optlen = (LONG)n;
    dst = (UBYTE *)optval;
    for (i = 0; i < n && i < 64; i++) dst[i] = data[2 + i];
    return r;
}

/* ---- getsockname / getpeername ------------------------------------------ */

static LONG _sockname(UBYTE opcode, LONG fd, APTR sa, LONG *addrlen,
                      struct BsdSession *sess, struct ExecBase *SysBase)
{
    struct BsdRspHdr *rsp;
    LONG   r;
    UBYTE *data, *dst;
    UBYTE  alen;
    UWORD  i;
    (void)SysBase;

    fill_hdr(sess, opcode, 2);
    w16(&sess->io_buf[4], (UWORD)fd);

    r = do_rpc(sess, SysBase, 6);
    if (r < 0 || !sa || !addrlen) return r;

    rsp  = (struct BsdRspHdr *)sess->io_buf;
    data = sess->io_buf + BSD_RSP_HDR_SIZE;
    if (rsp->datalen < 1) return r;

    alen = data[0];
    if (addrlen) *addrlen = (LONG)alen;
    dst = (UBYTE *)sa;
    for (i = 0; i < alen && i < 64; i++) dst[i] = data[1 + i];
    return r;
}

LONG bsd_getsockname(LONG fd __asm("d0"), APTR sa __asm("a0"), LONG *addrlen __asm("a1"),
                     struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    if (!sess) return -1;
    return _sockname(BSDOP_GETSOCKNAME, fd, sa, addrlen, sess, base->SysBase);
}

LONG bsd_getpeername(LONG fd __asm("d0"), APTR sa __asm("a0"), LONG *addrlen __asm("a1"),
                     struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    if (!sess) return -1;
    return _sockname(BSDOP_GETPEERNAME, fd, sa, addrlen, sess, base->SysBase);
}

/* ---- ioctlsocket() ------------------------------------------------------- */

LONG bsd_ioctlsocket(LONG fd __asm("d0"), LONG request __asm("d1"),
                     APTR argp __asm("a0"), struct BsdBase *base __asm("a6"))
{
    struct ExecBase   *SysBase = base->SysBase;
    struct BsdSession *sess    = find_session(base);
    ULONG  arg;
    (void)SysBase;
    if (!sess) return -1;

    arg = argp ? *(ULONG *)argp : 0UL;
    fill_hdr(sess, BSDOP_IOCTL, 10);
    w16(&sess->io_buf[4],  (UWORD)fd);
    w32(&sess->io_buf[6],  (ULONG)request);
    w32(&sess->io_buf[10], arg);
    return RPC_ZERO(do_rpc(sess, base->SysBase, 14));
}

/* ---- closesocket() ------------------------------------------------------- */

LONG bsd_closesocket(LONG fd __asm("d0"), struct BsdBase *base __asm("a6"))
{
    struct ExecBase   *SysBase = base->SysBase;
    struct BsdSession *sess    = find_session(base);
    (void)SysBase;
    if (!sess) return -1;

    fill_hdr(sess, BSDOP_CLOSE, 2);
    w16(&sess->io_buf[4], (UWORD)fd);
    return RPC_ZERO(do_rpc(sess, base->SysBase, 6));
}

/* ---- waitselect() -------------------------------------------------------- */

LONG bsd_waitselect(LONG nfds __asm("d0"),
                    fd_set *rfds __asm("a0"), fd_set *wfds __asm("a1"),
                    fd_set *efds __asm("a2"), struct timeval *tv __asm("a3"),
                    ULONG *sigmask __asm("d1"), struct BsdBase *base __asm("a6"))
{
    struct ExecBase   *SysBase = base->SysBase;
    struct BsdSession *sess    = find_session(base);
    struct BsdRspHdr  *rsp;
    ULONG  rm, wm, em, tv_sec, tv_usec;
    LONG   r;
    UBYTE *data;
    (void)SysBase; (void)sigmask;
    if (!sess) return -1;

    rm = rfds ? *rfds : 0UL;
    wm = wfds ? *wfds : 0UL;
    em = efds ? *efds : 0UL;
    if (tv) { tv_sec = (ULONG)tv->tv_sec; tv_usec = (ULONG)tv->tv_usec; }
    else    { tv_sec = 0xFFFFFFFFUL;      tv_usec = 0UL; }

    /* nfds(2) rmask(4) wmask(4) emask(4) tv_sec(4) tv_usec(4) = 22 bytes */
    fill_hdr(sess, BSDOP_WAITSELECT, 22);
    w16(&sess->io_buf[4],  (UWORD)nfds);
    w32(&sess->io_buf[6],  rm);
    w32(&sess->io_buf[10], wm);
    w32(&sess->io_buf[14], em);
    w32(&sess->io_buf[18], tv_sec);
    w32(&sess->io_buf[22], tv_usec);

    r = do_rpc(sess, base->SysBase, 26);
    /* Always clear output sigmask.  We forward WaitSelect to the Pi which
     * has no knowledge of Amiga signals.  Without this, callers that pass
     * sigmask=SIGBREAKF_CTRL_C (0x1000) see the unchanged input value on
     * return and incorrectly conclude that a break signal fired. */
    if (sigmask) *sigmask = 0;
    if (r < 0) return -1;

    rsp  = (struct BsdRspHdr *)sess->io_buf;
    data = sess->io_buf + BSD_RSP_HDR_SIZE;
    if (rsp->datalen >= 12) {
        if (rfds) *rfds = ((ULONG)data[0]<<24)|((ULONG)data[1]<<16)|((ULONG)data[2]<<8)|data[3];
        if (wfds) *wfds = ((ULONG)data[4]<<24)|((ULONG)data[5]<<16)|((ULONG)data[6]<<8)|data[7];
        if (efds) *efds = ((ULONG)data[8]<<24)|((ULONG)data[9]<<16)|((ULONG)data[10]<<8)|data[11];
    }
    return r;
}

/* ---- setsocketsignals() -------------------------------------------------- */

void bsd_setsocketsignals(ULONG d0 __asm("d0"), ULONG d1 __asm("d1"),
                          ULONG d2 __asm("d2"), struct BsdBase *base __asm("a6"))
{
    /* Not implemented — signal-driven sockets not supported */
    (void)d0; (void)d1; (void)d2; (void)base;
}

/* ---- getdtablesize() ----------------------------------------------------- */

LONG bsd_getdtablesize(struct BsdBase *base __asm("a6"))
{
    (void)base;
    return 32; /* FD_SETSIZE */
}

/* ---- obtainsocket / releasesocket ---------------------------------------- */

LONG bsd_obtainsocket(LONG d0 __asm("d0"), LONG d1 __asm("d1"),
                      LONG d2 __asm("d2"), LONG d3 __asm("d3"),
                      struct BsdBase *base __asm("a6"))
{ (void)d0; (void)d1; (void)d2; (void)d3; (void)base; return -1; }

LONG bsd_releasesocket(LONG d0 __asm("d0"), LONG d1 __asm("d1"),
                       struct BsdBase *base __asm("a6"))
{ (void)d0; (void)d1; (void)base; return -1; }

LONG bsd_releasecopyofsocket(LONG d0 __asm("d0"), LONG d1 __asm("d1"),
                              struct BsdBase *base __asm("a6"))
{ (void)d0; (void)d1; (void)base; return -1; }

/* ---- inet_ntoa() --------------------------------------------------------- */

STRPTR bsd_inet_ntoa(ULONG addr __asm("d0"), struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    BYTE  *p;
    UWORD  pos;
    UBYTE  bytes[4];
    UBYTE  i;

    if (!sess) return (STRPTR)"0.0.0.0";

    bytes[0] = (UBYTE)(addr >> 24);
    bytes[1] = (UBYTE)(addr >> 16);
    bytes[2] = (UBYTE)(addr >>  8);
    bytes[3] = (UBYTE)(addr);

    p   = sess->ntoa_buf;
    pos = 0;
    for (i = 0; i < 4; i++) {
        UBYTE v = bytes[i];
        if (v >= 100) { p[pos++] = (BYTE)('0' + v / 100); v %= 100;
                        p[pos++] = (BYTE)('0' + v /  10); v %= 10; }
        else if (v >= 10) { p[pos++] = (BYTE)('0' + v / 10); v %= 10; }
        p[pos++] = (BYTE)('0' + v);
        if (i < 3) p[pos++] = '.';
    }
    p[pos] = 0;
    return (STRPTR)p;
}

/* ---- inet_addr() --------------------------------------------------------- */

ULONG bsd_inet_addr(STRPTR s __asm("a0"), struct BsdBase *base __asm("a6"))
{
    /* Parse dotted-decimal "a.b.c.d" locally — no A314 needed */
    ULONG result = 0;
    UBYTE parts  = 0;
    ULONG cur    = 0;
    UBYTE c;
    (void)base;

    if (!s) return 0xFFFFFFFFUL;

    while ((c = (UBYTE)*s++) != 0) {
        if (c >= '0' && c <= '9') {
            cur = cur * 10 + (c - '0');
            if (cur > 255) return 0xFFFFFFFFUL;
        } else if (c == '.') {
            result = (result << 8) | (cur & 0xFF);
            cur = 0;
            parts++;
            if (parts > 3) return 0xFFFFFFFFUL;
        } else {
            return 0xFFFFFFFFUL;
        }
    }
    result = (result << 8) | (cur & 0xFF);
    parts++;
    if (parts != 4) return 0xFFFFFFFFUL;
    return result;
}

/* ---- inet_lnaof / inet_netof / inet_makeaddr / inet_network -------------- */

ULONG bsd_inet_lnaof(ULONG in __asm("d0"), struct BsdBase *base __asm("a6"))
{
    (void)base;
    if ((in & 0x80000000UL) == 0)          return in & 0x00FFFFFFUL; /* class A */
    if ((in & 0xC0000000UL) == 0x80000000UL) return in & 0x0000FFFFUL; /* class B */
    return in & 0x000000FFUL; /* class C */
}

ULONG bsd_inet_netof(ULONG in __asm("d0"), struct BsdBase *base __asm("a6"))
{
    (void)base;
    if ((in & 0x80000000UL) == 0)          return (in >> 24) & 0xFF;       /* class A */
    if ((in & 0xC0000000UL) == 0x80000000UL) return (in >> 16) & 0xFFFF;   /* class B */
    return (in >> 8) & 0xFFFFFFUL; /* class C */
}

ULONG bsd_inet_makeaddr(ULONG net __asm("d0"), ULONG host __asm("d1"),
                        struct BsdBase *base __asm("a6"))
{
    (void)base;
    if (net < 128UL)    return (net << 24) | (host & 0x00FFFFFFUL);
    if (net < 65536UL)  return (net << 16) | (host & 0x0000FFFFUL);
    return (net <<  8) | (host & 0x000000FFUL);
}

ULONG bsd_inet_network(STRPTR s __asm("a0"), struct BsdBase *base __asm("a6"))
{
    /* Parse network number — simplified: same as inet_addr but may omit trailing octets */
    return bsd_inet_addr(s, base);
}

/* ---- gethostbyname() ----------------------------------------------------- */

struct hostent *bsd_gethostbyname(STRPTR name __asm("a0"),
                                   struct BsdBase *base __asm("a6"))
{
    struct ExecBase   *SysBase = base->SysBase;
    struct BsdSession *sess    = find_session(base);
    struct BsdRspHdr  *rsp;
    LONG   r;
    UBYTE  namelen, i;
    UBYTE *data;
    (void)SysBase;

    if (!sess || !name) return NULL;

    namelen = 0;
    while (name[namelen] && namelen < 254) namelen++;

    /* args: namelen(1) name[namelen] */
    fill_hdr(sess, BSDOP_GETHOSTBYNAME, 1 + namelen);
    sess->io_buf[4] = namelen;
    for (i = 0; i < namelen; i++) sess->io_buf[5 + i] = (UBYTE)name[i];

    r = do_rpc(sess, base->SysBase, 5 + namelen);
    if (r <= 0) return NULL; /* error or no addresses */

    /* data = naddrs * 4 bytes (IPv4 in network byte order) */
    rsp  = (struct BsdRspHdr *)sess->io_buf;
    data = sess->io_buf + BSD_RSP_HDR_SIZE;
    if (rsp->datalen < 4) return NULL;

    /* Store first address as a ULONG in network byte order */
    sess->haddr = ((ULONG)data[0] << 24) | ((ULONG)data[1] << 16) |
                  ((ULONG)data[2] <<  8) |  (ULONG)data[3];

    /* h_name = the queried name */
    for (i = 0; i < namelen; i++) sess->hname[i] = name[i];
    sess->hname[namelen] = 0;

    return &sess->hent;
}

/* ---- gethostbyaddr() ----------------------------------------------------- */

struct hostent *bsd_gethostbyaddr(APTR addr __asm("a0"), LONG len __asm("d0"),
                                   LONG type __asm("d1"),
                                   struct BsdBase *base __asm("a6"))
{
    struct ExecBase   *SysBase = base->SysBase;
    struct BsdSession *sess    = find_session(base);
    struct BsdRspHdr  *rsp;
    UBYTE  alen, i;
    LONG   r;
    UBYTE *data;
    (void)SysBase;

    if (!sess || !addr || len < 4) return NULL;
    alen = (UBYTE)len;

    /* args: addrlen(1) addr[] type(2) */
    fill_hdr(sess, BSDOP_GETHOSTBYADDR, 1 + alen + 2);
    sess->io_buf[4] = alen;
    for (i = 0; i < alen; i++) sess->io_buf[5 + i] = ((UBYTE *)addr)[i];
    w16(&sess->io_buf[5 + alen], (UWORD)type);

    r = do_rpc(sess, base->SysBase, 4 + 1 + alen + 2);
    if (r < 0) return NULL;

    /* data = hostname bytes */
    rsp  = (struct BsdRspHdr *)sess->io_buf;
    data = sess->io_buf + BSD_RSP_HDR_SIZE;
    for (i = 0; i < rsp->datalen && i < 255; i++) sess->hname[i] = (BYTE)data[i];
    sess->hname[rsp->datalen < 255 ? rsp->datalen : 255] = 0;

    /* Store the queried address */
    if (alen >= 4)
        sess->haddr = ((ULONG)((UBYTE *)addr)[0] << 24) |
                      ((ULONG)((UBYTE *)addr)[1] << 16) |
                      ((ULONG)((UBYTE *)addr)[2] <<  8) |
                       (ULONG)((UBYTE *)addr)[3];

    return &sess->hent;
}

/* ---- getnetbyname / getnetbyaddr ----------------------------------------- */

struct netent *bsd_getnetbyname(STRPTR a0 __asm("a0"), struct BsdBase *base __asm("a6"))
{ (void)a0; (void)base; return NULL; }

struct netent *bsd_getnetbyaddr(ULONG d0 __asm("d0"), LONG d1 __asm("d1"),
                                 struct BsdBase *base __asm("a6"))
{ (void)d0; (void)d1; (void)base; return NULL; }

/* ---- getservbyname / getservbyport --------------------------------------- */

struct servent *bsd_getservbyname(STRPTR name __asm("a0"), STRPTR proto __asm("a1"),
                                   struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    struct BsdRspHdr  *rsp;
    UBYTE  namelen, protolen, i;
    LONG   r;
    UBYTE *data;

    if (!sess || !name) return NULL;

    namelen  = 0; while (name[namelen]  && namelen  < 63) namelen++;
    protolen = 0;
    if (proto) { while (proto[protolen] && protolen < 15) protolen++; }

    /* args: namelen(1) name[] protolen(1) proto[] */
    fill_hdr(sess, BSDOP_GETSERVBYNAME, 2 + namelen + protolen);
    sess->io_buf[4] = namelen;
    for (i = 0; i < namelen;  i++) sess->io_buf[5 + i]           = (UBYTE)name[i];
    sess->io_buf[5 + namelen] = protolen;
    for (i = 0; i < protolen; i++) sess->io_buf[6 + namelen + i] = (UBYTE)proto[i];

    r = do_rpc(sess, base->SysBase, 6 + namelen + protolen);
    if (r < 0) return NULL;

    /* result = port (host order); data = proto name bytes (no NUL) */
    rsp  = (struct BsdRspHdr *)sess->io_buf;
    data = sess->io_buf + BSD_RSP_HDR_SIZE;

    for (i = 0; i < namelen;          i++) sess->sent_name[i]  = name[i];
    sess->sent_name[namelen] = 0;

    for (i = 0; i < rsp->datalen && i < 15; i++) sess->sent_proto[i] = (BYTE)data[i];
    sess->sent_proto[rsp->datalen < 15 ? rsp->datalen : 15] = 0;

    sess->sent.s_port = (int)r;  /* big-endian result = network order on m68k */
    return &sess->sent;
}

struct servent *bsd_getservbyport(LONG port __asm("d0"), STRPTR proto __asm("a0"),
                                   struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    struct BsdRspHdr  *rsp;
    UBYTE  protolen, i;
    LONG   r;
    UBYTE *data;

    if (!sess) return NULL;

    protolen = 0;
    if (proto) { while (proto[protolen] && protolen < 15) protolen++; }

    /* args: port(2) protolen(1) proto[] */
    fill_hdr(sess, BSDOP_GETSERVBYPORT, 3 + protolen);
    w16(&sess->io_buf[4], (UWORD)port);
    sess->io_buf[6] = protolen;
    for (i = 0; i < protolen; i++) sess->io_buf[7 + i] = (UBYTE)proto[i];

    r = do_rpc(sess, base->SysBase, 7 + protolen);
    if (r < 0) return NULL;

    /* result = port (host order); data = service name bytes (no NUL) */
    rsp  = (struct BsdRspHdr *)sess->io_buf;
    data = sess->io_buf + BSD_RSP_HDR_SIZE;

    for (i = 0; i < rsp->datalen && i < 63; i++) sess->sent_name[i] = (BYTE)data[i];
    sess->sent_name[rsp->datalen < 63 ? rsp->datalen : 63] = 0;

    if (proto) {
        for (i = 0; i < protolen; i++) sess->sent_proto[i] = proto[i];
        sess->sent_proto[protolen] = 0;
    } else {
        sess->sent_proto[0] = 0;
    }

    sess->sent.s_port = (int)port;  /* caller passes network-order port; echo it back */
    return &sess->sent;
}

/* ---- getprotobyname / getprotobynumber ----------------------------------- */
/*
 * Protocol numbers are IANA-standardised and never change, so we resolve
 * them locally without a Pi round-trip.
 */

static const struct { const char *name; int proto; } _proto_table[] = {
    { "ip",      0   },
    { "icmp",    1   },
    { "igmp",    2   },
    { "tcp",     6   },
    { "udp",     17  },
    { "raw",     255 },
    { NULL,      0   }
};

static struct protoent *_fill_pent(struct BsdSession *sess,
                                   const char *name, int proto)
{
    UBYTE i;
    for (i = 0; name[i] && i < 15; i++) sess->pent_name[i] = name[i];
    sess->pent_name[i]  = 0;
    sess->pent.p_proto  = proto;
    return &sess->pent;
}

struct protoent *bsd_getprotobyname(STRPTR name __asm("a0"),
                                     struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    UWORD i;
    if (!sess || !name) return NULL;
    for (i = 0; _proto_table[i].name; i++) {
        const char *p = _proto_table[i].name;
        const char *n = (const char *)name;
        UWORD j = 0;
        while (p[j] && n[j] && p[j] == n[j]) j++;
        if (!p[j] && !n[j])
            return _fill_pent(sess, _proto_table[i].name, _proto_table[i].proto);
    }
    return NULL;
}

struct protoent *bsd_getprotobynumber(LONG proto __asm("d0"),
                                       struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    UWORD i;
    if (!sess) return NULL;
    for (i = 0; _proto_table[i].name; i++) {
        if (_proto_table[i].proto == (int)proto)
            return _fill_pent(sess, _proto_table[i].name, _proto_table[i].proto);
    }
    return NULL;
}

/* ---- vsyslog() ----------------------------------------------------------- */

void bsd_vsyslog(LONG d0 __asm("d0"), STRPTR a0 __asm("a0"), APTR a1 __asm("a1"),
                 struct BsdBase *base __asm("a6"))
{ (void)d0; (void)a0; (void)a1; (void)base; }

/* ---- dup2socket() -------------------------------------------------------- */

LONG bsd_dup2socket(LONG d0 __asm("d0"), LONG d1 __asm("d1"),
                    struct BsdBase *base __asm("a6"))
{ (void)d0; (void)d1; (void)base; return -1; }

/* ---- sendmsg / recvmsg --------------------------------------------------- */

LONG bsd_sendmsg(LONG d0 __asm("d0"), APTR a0 __asm("a0"), LONG d1 __asm("d1"),
                 struct BsdBase *base __asm("a6"))
{ (void)d0; (void)a0; (void)d1; (void)base; return -1; }

LONG bsd_recvmsg(LONG d0 __asm("d0"), APTR a0 __asm("a0"), LONG d1 __asm("d1"),
                 struct BsdBase *base __asm("a6"))
{ (void)d0; (void)a0; (void)d1; (void)base; return -1; }

/* ---- gethostname() ------------------------------------------------------- */

LONG bsd_gethostname(APTR buf __asm("a0"), LONG buflen __asm("d0"),
                     struct BsdBase *base __asm("a6"))
{
    struct ExecBase   *SysBase = base->SysBase;
    struct BsdSession *sess    = find_session(base);
    struct BsdRspHdr  *rsp;
    LONG   r;
    UBYTE *data, *dst;
    UWORD  n, i;
    (void)SysBase;

    if (!sess || !buf || buflen <= 0) return -1;

    fill_hdr(sess, BSDOP_GETHOSTNAME, 2);
    w16(&sess->io_buf[4], (UWORD)buflen);
    r = do_rpc(sess, base->SysBase, 6);
    if (r < 0) return -1;

    rsp  = (struct BsdRspHdr *)sess->io_buf;
    data = sess->io_buf + BSD_RSP_HDR_SIZE;
    n    = rsp->datalen;
    if (n >= (UWORD)buflen) n = (UWORD)buflen - 1;

    dst = (UBYTE *)buf;
    for (i = 0; i < n; i++) dst[i] = data[i];
    dst[n] = 0;
    return 0;
}

/* ---- gethostid() --------------------------------------------------------- */

ULONG bsd_gethostid(struct BsdBase *base __asm("a6"))
{ (void)base; return 0; }

/* ---- socketbasetaglist() ------------------------------------------------- */

LONG bsd_socketbasetaglist(APTR a0 __asm("a0"), struct BsdBase *base __asm("a6"))
{ (void)a0; (void)base; return 0; }

/* ---- getsocketevents() --------------------------------------------------- */

ULONG bsd_getsocketevents(APTR a0 __asm("a0"), struct BsdBase *base __asm("a6"))
{ (void)a0; (void)base; return 0; }
