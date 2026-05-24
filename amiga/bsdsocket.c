/*
 * bsdsocket.c — a314bsd bsdsocket.library v5.0
 *
 * v5 architecture (vs v4):
 *   - One dispatcher task per OpenLibrary.  The dispatcher owns the A314
 *     connection and does ALL A314_WRITE / A314_READ I/O.
 *   - Library functions called by the application (in the application's task
 *     context) just build a request, hand it to the dispatcher via a message
 *     port, and Wait() ONCE for the reply.  No matter how many physical A314
 *     packets are needed to move the data, the caller's task does exactly
 *     one Wait per library call.
 *   - The wire protocol is the v5 framing in include/bsd_proto.h: one REQ
 *     header packet (with inline args), optional input-data chunks, one RES
 *     header packet, optional output-data chunks.  Pi side does one Linux
 *     syscall per Amiga library call.
 *
 * Why this matters for wget reliability: v4 did N Pi round-trips per
 * bsd_recv (one per 245-byte chunk), giving 2N Wait() points where another
 * Amiga task could leave the shared FPU exception flags set.  When wget
 * resumed, its mathieeedoubbas calls inherited the poisoned FPU state,
 * causing NaN/Inf in its bandwidth and percentage math — and tripping
 * "percentage <= 100" or "msecs >= 0" asserts ~33% of the time.  Moving the
 * Wait()s into the dispatcher task means wget's calling task does one Wait
 * per recv, matching the behaviour of working stacks (Roadshow, Niklas).
 */

#include <exec/types.h>
#include <exec/execbase.h>
#include <exec/libraries.h>
#include <exec/lists.h>
#include <exec/memory.h>
#include <exec/io.h>
#include <exec/ports.h>
#include <exec/tasks.h>
#include <exec/semaphores.h>
#include <devices/timer.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <dos/dostags.h>

#include <proto/exec.h>
#include <proto/dos.h>

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
    ULONG            next_socket_id;   /* monotonic A314 socket ID */
};

/* ---- Request packet (caller -> dispatcher) ------------------------------- */

#define DISP_STACK_SIZE  4096
#define DISP_TASK_PRI    0
#define DISP_TASK_NAME   "a314bsd.disp"

/* A BsdRequest is exec.message passed from a caller task to the dispatcher.
 * The caller fills the fields, PutMsg's it to the dispatcher's port, then
 * Wait()s on its own reply port for the dispatcher to fill in result/errno
 * and ReplyMsg.  Only ONE request is in flight per session at a time. */
struct BsdRequest {
    struct Message     msg;       /* embedded — for PutMsg/ReplyMsg */
    UBYTE              opcode;    /* BSDOP_* */
    UBYTE              args[BSD_MAX_REQ_ARGS];
    UWORD              arglen;    /* bytes filled in args[] */
    /* Input data: bytes to send to Pi after the REQ header (e.g. send buffer) */
    CONST_APTR         indata;
    ULONG              inlen;
    /* Output buffer: where dispatcher writes data Pi sends back (recv buffer) */
    APTR               outdata;
    ULONG              outmax;
    /* Filled by dispatcher: */
    LONG               result;    /* >= 0 success / < 0 = -errno style */
    LONG               errno_val; /* Pi's errno (BSD/AmiTCP numbering) */
    ULONG              outlen;    /* bytes written to outdata[] */
};

/* ---- Global DOSBase (kept open forever once first opened) --------------- */
/* CreateNewProcTags creates a dos.library-managed Process — dos.library
 * must stay open for that process's lifetime AND when it exits.  Closing
 * dos.library right after CreateNewProcTags can crash the new process.
 * Same applies to Delay() in bsd_close_lib. */
static struct Library         *s_DOSBase             = NULL;
static struct SignalSemaphore  s_DOSBase_sema;
static BOOL                    s_DOSBase_sema_inited = FALSE;

static struct Library *get_dosbase(struct ExecBase *SysBase)
{
    if (s_DOSBase) return s_DOSBase;
    if (!s_DOSBase_sema_inited) {
        InitSemaphore(&s_DOSBase_sema);
        s_DOSBase_sema_inited = TRUE;
    }
    ObtainSemaphore(&s_DOSBase_sema);
    if (!s_DOSBase) s_DOSBase = OpenLibrary((STRPTR)"dos.library", 0);
    ReleaseSemaphore(&s_DOSBase_sema);
    return s_DOSBase;
}

/* ---- Per-OpenLibrary session -------------------------------------------- */

struct BsdSession {
    struct MinNode         node;
    struct Task           *caller_task;   /* the task that opened us */

    /* Dispatcher: per-session task that owns the A314 connection. */
    struct Task           *disp_task;
    struct MsgPort        *disp_port;     /* dispatcher's incoming request port */
    BYTE                   disp_kill_sig; /* allocated in dispatcher; we Signal it to ask exit */

    /* Reply port (lives in caller's task) for receiving dispatcher's replies */
    struct MsgPort         reply_port;
    BYTE                   reply_sig_bit;

    /* The one in-flight request (reused; we serialise per-session) */
    struct BsdRequest      req;

    /* Errno bookkeeping for SetErrnoPtr / SocketBaseTagList(SBTC_ERRNO*) */
    LONG                   errno_val;
    LONG                  *errno_ptr;
    LONG                  *h_errno_ptr;

    /* For hostent / inet_ntoa result buffers returned by reference */
    BYTE                   ntoa_buf[20];
    struct hostent         hent;
    BYTE                   hname[256];
    ULONG                  haddr;
    APTR                   haddr_list[2];
    APTR                   haliases[1];

    /* protoent buffer for getprotobyname/getprotobynumber (local, no Pi).
     * Returned by reference; same buffer reused across calls. */
    struct protoent        pent;
    BYTE                   pent_name[16];
    APTR                   pent_aliases[1];   /* always {NULL} */
};

/* Parameters passed from bsd_open to the dispatcher task at AddTask time.
 * Allocated by bsd_open, freed by bsd_open after dispatcher signals ready.
 *
 * The dispatcher CREATES its own MsgPort using its own signal allocation
 * (signal bits are per-task in AmigaOS), then writes the port pointer back
 * here so the caller can use it for PutMsg. */
struct DispStartup {
    struct ExecBase       *SysBase;
    struct BsdSession     *sess;
    ULONG                  socket_id;     /* A314 channel ID to use for CONNECT */
    struct Task           *parent;        /* signal back when ready or failed */
    BYTE                   parent_sig;    /* signal bit (allocated in parent) */
    /* Filled by dispatcher before signalling parent: */
    struct MsgPort        *disp_port_out; /* dispatcher's request port */
    BYTE                   kill_sig_out;  /* signal bit dispatcher allocated for shutdown */
    BOOL                   ready_ok;      /* TRUE on success */
};

/* ---- Forward decls ------------------------------------------------------- */

static struct BsdSession *find_session(struct BsdBase *base);
static void dispatcher_entry(void);
static BOOL do_rpc(struct BsdSession *sess);
static void w16(UBYTE *p, UWORD v);
static void w32(UBYTE *p, ULONG v);

/* ---- Low-level helpers --------------------------------------------------- */

static void w16(UBYTE *p, UWORD v) { p[0] = v >> 8; p[1] = v; }
static void w32(UBYTE *p, ULONG v) { p[0] = v>>24; p[1] = v>>16; p[2] = v>>8; p[3] = v; }

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
        if (s->caller_task == me) return s;
    }
    return NULL;
}

/* ---- do_rpc: caller-side RPC to dispatcher ------------------------------ */
/*
 * Build the request fields in sess->req before calling.  This function does
 * the PutMsg/WaitPort/GetMsg dance.  Caller's task Wait()s exactly once.
 * Returns TRUE on protocol success (result/errno filled), FALSE on disaster
 * (dispatcher gone, signal failure, etc.).
 */
static BOOL do_rpc(struct BsdSession *sess)
{
    /* SysBase is needed for PutMsg/WaitPort.  In the caller's task context
     * we get it from address 4 to avoid threading dependencies. */
    struct ExecBase *SysBase = *(struct ExecBase **)4UL;

    if (!sess->disp_task) {
        sess->req.result    = -1;
        sess->req.errno_val = 5;  /* EIO */
        return FALSE;
    }

    sess->req.msg.mn_ReplyPort = &sess->reply_port;
    sess->req.msg.mn_Length    = sizeof(struct BsdRequest);
    PutMsg(sess->disp_port, &sess->req.msg);
    WaitPort(&sess->reply_port);
    (void)GetMsg(&sess->reply_port);
    return TRUE;
}

/* ---- Dispatcher task ---------------------------------------------------- */
/*
 * Entry point for the per-session dispatcher task.  Pulls its startup
 * parameters from a global passing slot (set up by bsd_open), opens
 * a314.device, registers as a CONNECT to the "bsdsocket" service, then
 * loops processing requests from the session's MsgPort.
 *
 * The dispatcher does ALL the A314_WRITE / A314_READ work.  Each request:
 *   1. Write REQ header packet.
 *   2. Write inlen bytes of input data (in MAX_CHUNK-sized A314_WRITEs).
 *   3. Read RES header packet (one A314_READ).
 *   4. Read outlen bytes of output data into caller's buffer (multiple
 *      A314_READs, each at most MAX_CHUNK = 252 bytes).
 *   5. ReplyMsg back to caller.
 *
 * From the caller's perspective, that whole sequence is one Wait().
 */

/* The dispatcher passes startup state via a global slot — set by bsd_open
 * before AddTask, read by dispatcher immediately after start.  This avoids
 * needing to allocate-and-free a separate startup struct that the dispatcher
 * has to figure out to free. */
static struct DispStartup *s_disp_startup = NULL;
static struct SignalSemaphore s_disp_startup_sema;
static BOOL                   s_disp_startup_sema_inited = FALSE;

static void dispatcher_entry(void)
{
    struct ExecBase       *SysBase = *(struct ExecBase **)4UL;
    struct DispStartup    *start;
    struct BsdSession     *sess;
    ULONG                  socket_id;
    struct MsgPort        *a314_port  = NULL;  /* reply port for A314 IO */
    struct MsgPort        *req_port   = NULL;  /* incoming request port */
    struct A314_IORequest *ior        = NULL;
    UBYTE                  io_buf[BSD_MAX_CHUNK];
    BOOL                   running    = TRUE;
    BYTE                   kill_sig   = -1;

    /* Pick up our startup info from the global slot.  Parent holds the
     * semaphore around this so only one dispatcher can start at a time. */
    start = s_disp_startup;
    s_disp_startup = NULL;
    sess = start->sess;
    socket_id = start->socket_id;

    /* Allocate the kill signal — must be from THIS task's signal pool. */
    kill_sig = AllocSignal(-1);
    if (kill_sig == -1) goto fail_start;

    /* Create our request port — signal bit allocated from THIS task.  Caller
     * will PutMsg to this port; Signal will wake us correctly. */
    req_port = CreateMsgPort();
    if (!req_port) goto fail_start;

    /* Create A314 IO request + reply port. */
    a314_port = CreateMsgPort();
    if (!a314_port) goto fail_start;
    ior = (struct A314_IORequest *)CreateIORequest(a314_port, sizeof(struct A314_IORequest));
    if (!ior) goto fail_start;
    if (OpenDevice((STRPTR)A314_NAME, 0, (struct IORequest *)ior, 0) != 0)
        goto fail_start;

    /* Connect to the "bsdsocket" Pi service. */
    ior->a314_Socket  = socket_id;
    ior->a314_Buffer  = (STRPTR)"bsdsocket";
    ior->a314_Length  = 9;
    ior->a314_Request.io_Command = A314_CONNECT;
    if (DoIO((struct IORequest *)ior) != A314_CONNECT_OK)
        goto fail_after_open;

    /* Notify parent we're ready — hand over port + kill signal numbers. */
    start->disp_port_out = req_port;
    start->kill_sig_out  = kill_sig;
    start->ready_ok      = TRUE;
    Signal(start->parent, 1L << start->parent_sig);
    start = NULL;   /* parent will free it */

    /* Main loop: wait on either the request port or the kill signal. */
    while (running) {
        ULONG sigs = Wait((1L << req_port->mp_SigBit) | (1L << kill_sig));
        if (sigs & (1L << kill_sig)) {
            running = FALSE;
            break;
        }
        struct BsdRequest *req;
        while ((req = (struct BsdRequest *)GetMsg(req_port)) != NULL) {
            UBYTE  hdr[BSD_REQ_HDR_SIZE];
            UBYTE  res_hdr[BSD_RES_HDR_SIZE];
            CONST_APTR src;
            ULONG  remaining;
            UWORD  chunk;

            /* --- Send REQ header packet --- */
            hdr[0] = req->opcode;
            hdr[1] = 0;                       /* seq (unused for now) */
            w16(&hdr[2], req->arglen);
            w16(&hdr[4], (UWORD)req->inlen);
            /* The REQ header + args go in ONE A314_WRITE so Pi sees them as
             * a single PKT_DATA.  We assume arglen <= BSD_MAX_REQ_ARGS so
             * total <= 252. */
            {
                UBYTE pkt[BSD_REQ_HDR_SIZE + BSD_MAX_REQ_ARGS];
                UWORD i;
                for (i = 0; i < BSD_REQ_HDR_SIZE; i++) pkt[i] = hdr[i];
                for (i = 0; i < req->arglen; i++)
                    pkt[BSD_REQ_HDR_SIZE + i] = req->args[i];
                ior->a314_Request.io_Command = A314_WRITE;
                ior->a314_Buffer = (STRPTR)pkt;
                ior->a314_Length = (WORD)(BSD_REQ_HDR_SIZE + req->arglen);
                if (DoIO((struct IORequest *)ior) != A314_WRITE_OK) {
                    req->result = -1; req->errno_val = 5;
                    goto reply;
                }
            }

            /* --- Send input data chunks (if any) --- */
            src       = req->indata;
            remaining = req->inlen;
            while (remaining > 0) {
                chunk = (remaining > BSD_MAX_CHUNK) ? BSD_MAX_CHUNK : (UWORD)remaining;
                ior->a314_Request.io_Command = A314_WRITE;
                ior->a314_Buffer = (STRPTR)src;
                ior->a314_Length = (WORD)chunk;
                if (DoIO((struct IORequest *)ior) != A314_WRITE_OK) {
                    req->result = -1; req->errno_val = 5;
                    goto reply;
                }
                src = (CONST_APTR)((UBYTE *)src + chunk);
                remaining -= chunk;
            }

            /* --- Receive RES header packet --- */
            ior->a314_Request.io_Command = A314_READ;
            ior->a314_Buffer = (STRPTR)io_buf;
            ior->a314_Length = BSD_MAX_CHUNK;
            if (DoIO((struct IORequest *)ior) != A314_READ_OK
                || ior->a314_Length < BSD_RES_HDR_SIZE) {
                req->result = -1; req->errno_val = 6;  /* ENXIO */
                goto reply;
            }
            {
                UWORD i;
                for (i = 0; i < BSD_RES_HDR_SIZE; i++) res_hdr[i] = io_buf[i];
            }
            /* Decode: seq(1) result(4) errno(4) outlen(2) */
            req->result = ((LONG)res_hdr[1] << 24) | ((LONG)res_hdr[2] << 16)
                        | ((LONG)res_hdr[3] <<  8) |  (LONG)res_hdr[4];
            req->errno_val = ((LONG)res_hdr[5] << 24) | ((LONG)res_hdr[6] << 16)
                           | ((LONG)res_hdr[7] <<  8) |  (LONG)res_hdr[8];
            req->outlen = ((ULONG)res_hdr[9] << 8) | (ULONG)res_hdr[10];

            /* --- Receive output data chunks (if any) --- */
            {
                UBYTE *dst       = (UBYTE *)req->outdata;
                ULONG  to_copy   = (req->outlen < req->outmax) ? req->outlen : req->outmax;
                ULONG  to_discard = req->outlen - to_copy;
                ULONG  copied = 0;
                /* Any leftover bytes from the RES read are not present —
                 * RES header packet is its own A314 packet. */
                while (copied < to_copy) {
                    ULONG want = to_copy - copied;
                    if (want > BSD_MAX_CHUNK) want = BSD_MAX_CHUNK;
                    ior->a314_Request.io_Command = A314_READ;
                    ior->a314_Buffer = (STRPTR)(dst + copied);
                    ior->a314_Length = (WORD)want;
                    if (DoIO((struct IORequest *)ior) != A314_READ_OK) {
                        req->result = -1; req->errno_val = 6;
                        goto reply;
                    }
                    copied += ior->a314_Length;
                }
                /* Discard any extra bytes Pi sent (in case maxlen was less
                 * than what Pi returned).  Shouldn't happen if Pi respects
                 * the maxlen arg, but defensive. */
                while (to_discard > 0) {
                    ULONG want = (to_discard > BSD_MAX_CHUNK) ? BSD_MAX_CHUNK : to_discard;
                    ior->a314_Request.io_Command = A314_READ;
                    ior->a314_Buffer = (STRPTR)io_buf;
                    ior->a314_Length = (WORD)want;
                    if (DoIO((struct IORequest *)ior) != A314_READ_OK) break;
                    to_discard -= ior->a314_Length;
                }
            }

reply:
            /* Update session-level errno cache; the library function that
             * called us will optionally propagate to *errno_ptr. */
            sess->errno_val = (req->result < 0) ? req->errno_val : 0;
            ReplyMsg(&req->msg);
        }
    }

    /* --- Cleanup --- */
    ior->a314_Request.io_Command = A314_EOS;
    DoIO((struct IORequest *)ior);
    CloseDevice((struct IORequest *)ior);
    DeleteIORequest((struct IORequest *)ior);
    DeleteMsgPort(a314_port);
    DeleteMsgPort(req_port);
    FreeSignal(kill_sig);
    sess->disp_task = NULL;
    /* Created via CreateNewProc → dos.library handles cleanup when we return. */
    return;

fail_after_open:
    if (ior) DeleteIORequest((struct IORequest *)ior);
fail_start:
    if (a314_port) DeleteMsgPort(a314_port);
    if (req_port)  DeleteMsgPort(req_port);
    if (kill_sig != -1) FreeSignal(kill_sig);
    if (start) {
        start->ready_ok = FALSE;
        Signal(start->parent, 1L << start->parent_sig);
    }
    sess->disp_task = NULL;
    return;
}

/* ---- Open / Close ------------------------------------------------------- */

struct BsdBase *bsd_open(struct BsdBase *base)
{
    struct ExecBase    *SysBase = base->SysBase;
    struct BsdSession  *sess;
    struct DispStartup *startup;
    BYTE                ready_sig;
    ULONG               sigs;

    sess = (struct BsdSession *)AllocVec(sizeof(*sess), MEMF_PUBLIC | MEMF_CLEAR);
    if (!sess) return NULL;

    sess->caller_task   = FindTask(NULL);
    sess->disp_kill_sig = -1;

    /* Reply port for receiving dispatcher's ReplyMsg.  Built manually so
     * we can hard-code the signal bit allocated from the caller's task. */
    sess->reply_sig_bit = AllocSignal(-1);
    if (sess->reply_sig_bit == -1) goto fail;
    sess->reply_port.mp_Node.ln_Type = NT_MSGPORT;
    sess->reply_port.mp_Flags        = PA_SIGNAL;
    sess->reply_port.mp_SigBit       = sess->reply_sig_bit;
    sess->reply_port.mp_SigTask      = sess->caller_task;
    /* Manual NewList equivalent — avoids needing the NewList symbol. */
    sess->reply_port.mp_MsgList.lh_Head     = (struct Node *)&sess->reply_port.mp_MsgList.lh_Tail;
    sess->reply_port.mp_MsgList.lh_Tail     = NULL;
    sess->reply_port.mp_MsgList.lh_TailPred = (struct Node *)&sess->reply_port.mp_MsgList.lh_Head;

    /* Dispatcher's request port is created INSIDE the dispatcher task so
     * the port's signal bit is allocated from the dispatcher's signal pool
     * (signals are per-task on AmigaOS).  We fill sess->disp_port from the
     * startup struct after the dispatcher signals ready. */

    /* Allocate signal we'll wait on for "dispatcher is ready". */
    ready_sig = AllocSignal(-1);
    if (ready_sig == -1) goto fail_reply;

    /* Build the startup descriptor.  Use the global slot + semaphore to
     * hand it to the new task (AddTask doesn't carry a user arg). */
    if (!s_disp_startup_sema_inited) {
        InitSemaphore(&s_disp_startup_sema);
        s_disp_startup_sema_inited = TRUE;
    }
    ObtainSemaphore(&s_disp_startup_sema);

    startup = AllocMem(sizeof(*startup), MEMF_PUBLIC | MEMF_CLEAR);
    if (!startup) { ReleaseSemaphore(&s_disp_startup_sema); goto fail_sig; }

    startup->SysBase     = SysBase;
    startup->sess        = sess;
    startup->socket_id   = ++base->next_socket_id;
    startup->parent      = sess->caller_task;
    startup->parent_sig  = ready_sig;
    startup->ready_ok    = FALSE;
    s_disp_startup       = startup;

    /* Spawn the dispatcher Process.  DOSBase is held globally (opened
     * lazily, never closed) so the just-started Process can rely on
     * dos.library staying open for its entire lifetime. */
    {
        struct Library *DOSBase = get_dosbase(SysBase);
        struct Process *proc = NULL;
        if (DOSBase) {
            proc = CreateNewProcTags(
                NP_Entry,     (Tag)dispatcher_entry,
                NP_Name,      (Tag)DISP_TASK_NAME,
                NP_StackSize, (Tag)DISP_STACK_SIZE,
                NP_Priority,  (Tag)DISP_TASK_PRI,
                TAG_DONE);
        }
        if (!proc) {
            FreeMem(startup, sizeof(*startup));
            s_disp_startup = NULL;
            ReleaseSemaphore(&s_disp_startup_sema);
            goto fail_sig;
        }
        sess->disp_task = (struct Task *)proc;
    }

    /* Wait for dispatcher to signal ready (or failure). */
    sigs = Wait(1L << ready_sig);
    (void)sigs;
    FreeSignal(ready_sig);

    if (!startup->ready_ok) {
        FreeMem(startup, sizeof(*startup));
        ReleaseSemaphore(&s_disp_startup_sema);
        sess->disp_task = NULL;
        goto fail_port;
    }
    /* Pick up the port + kill-sig values the dispatcher filled in. */
    sess->disp_port = startup->disp_port_out;
    sess->disp_kill_sig = startup->kill_sig_out;
    FreeMem(startup, sizeof(*startup));
    ReleaseSemaphore(&s_disp_startup_sema);

    /* Wire up the hostent skeleton */
    sess->haddr_list[0]    = (APTR)&sess->haddr;
    sess->haddr_list[1]    = NULL;
    sess->haliases[0]      = NULL;
    sess->hent.h_name      = sess->hname;
    sess->hent.h_aliases   = (char **)sess->haliases;
    sess->hent.h_addrtype  = AF_INET;
    sess->hent.h_length    = 4;
    sess->hent.h_addr_list = (char **)sess->haddr_list;

    /* Wire up the protoent skeleton (used by getprotobyname/number) */
    sess->pent_aliases[0]  = NULL;
    sess->pent.p_name      = sess->pent_name;
    sess->pent.p_aliases   = (char **)sess->pent_aliases;

    AddTail((struct List *)&base->sessions, (struct Node *)&sess->node);
    base->lib.lib_OpenCnt++;
    return base;

fail_sig:
    FreeSignal(ready_sig);
fail_port:
    /* Nothing to do — the disp_port lives in the dispatcher task and is
     * only handed to us via startup->disp_port_out on success. */
fail_reply:
    FreeSignal(sess->reply_sig_bit);
fail:
    FreeVec(sess);
    return NULL;
}

void bsd_close_lib(struct BsdBase *base)
{
    struct ExecBase   *SysBase = base->SysBase;
    struct BsdSession *sess    = find_session(base);

    if (sess) {
        struct Library *DOSBase = get_dosbase(SysBase);
        Remove((struct Node *)&sess->node);

        /* Ask dispatcher to exit, poll-wait for it to clear disp_task as
         * the "I'm gone" indicator. */
        if (sess->disp_task && sess->disp_kill_sig != -1) {
            Signal(sess->disp_task, 1L << sess->disp_kill_sig);
            while (sess->disp_task) {
                if (DOSBase) Delay(1);   /* 1 tick = 20 ms */
            }
        }

        /* disp_port and disp_kill_sig live in the dispatcher's task — it
         * cleans them up itself before returning (and dos.library cleans up
         * the dispatcher process). */
        FreeSignal(sess->reply_sig_bit);
        FreeVec(sess);
    }
    base->lib.lib_OpenCnt--;
}

/* ---- Library functions called by the application ------------------------- */
/*
 * Each library function (called in the caller's task) just builds a request
 * in sess->req, calls do_rpc, then translates the result.  The caller does
 * exactly ONE Wait() per call.
 */

/* ---- errno ------------------------------------------------------------- */

LONG bsd_errno(struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    return sess ? sess->errno_val : 0;
}

void bsd_seterrnoptr(APTR a0 __asm("a0"), LONG d0 __asm("d0"),
                     struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    (void)d0;
    if (sess) sess->errno_ptr = (LONG *)a0;
}

/* Helper: after a do_rpc, write the errno to caller's errno cell if set. */
static void propagate_errno(struct BsdSession *sess)
{
    if (sess->errno_ptr) *sess->errno_ptr = sess->errno_val;
}

/* ---- socket() --------------------------------------------------------- */

LONG bsd_socket(LONG domain __asm("d0"), LONG type __asm("d1"),
                LONG proto __asm("d2"), struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    if (!sess) return -1;

    sess->req.opcode = BSDOP_SOCKET;
    sess->req.arglen = 6;
    w16(&sess->req.args[0], (UWORD)domain);
    w16(&sess->req.args[2], (UWORD)type);
    w16(&sess->req.args[4], (UWORD)proto);
    sess->req.indata = NULL; sess->req.inlen = 0;
    sess->req.outdata = NULL; sess->req.outmax = 0;
    do_rpc(sess);
    propagate_errno(sess);
    return sess->req.result;
}

/* ---- close() ---------------------------------------------------------- */

LONG bsd_closesocket(LONG fd __asm("d0"), struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    if (!sess) return -1;
    sess->req.opcode = BSDOP_CLOSE;
    sess->req.arglen = 2;
    w16(&sess->req.args[0], (UWORD)fd);
    sess->req.indata = NULL; sess->req.inlen = 0;
    sess->req.outdata = NULL; sess->req.outmax = 0;
    do_rpc(sess);
    propagate_errno(sess);
    return sess->req.result;
}

/* ---- connect() -------------------------------------------------------- */

LONG bsd_connect(LONG fd __asm("d0"), APTR sa __asm("a0"), LONG addrlen __asm("d1"),
                 struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    UWORD i;
    if (!sess) return -1;
    if (addrlen < 0 || addrlen > 64) addrlen = 16;

    sess->req.opcode = BSDOP_CONNECT;
    sess->req.arglen = 3 + (UWORD)addrlen;
    w16(&sess->req.args[0], (UWORD)fd);
    sess->req.args[2] = (UBYTE)addrlen;
    for (i = 0; i < (UWORD)addrlen; i++)
        sess->req.args[3 + i] = ((UBYTE *)sa)[i];
    sess->req.indata = NULL; sess->req.inlen = 0;
    sess->req.outdata = NULL; sess->req.outmax = 0;
    do_rpc(sess);
    propagate_errno(sess);
    return sess->req.result;
}

/* ---- send() ----------------------------------------------------------- */

LONG bsd_send(LONG fd __asm("d0"), APTR buf __asm("a0"), LONG len __asm("d1"),
              LONG flags __asm("d2"), struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    if (!sess || len <= 0) return (len == 0) ? 0 : -1;

    sess->req.opcode = BSDOP_SEND;
    sess->req.arglen = 4;
    w16(&sess->req.args[0], (UWORD)fd);
    w16(&sess->req.args[2], (UWORD)flags);
    sess->req.indata = buf;
    sess->req.inlen  = (ULONG)len;
    sess->req.outdata = NULL; sess->req.outmax = 0;
    do_rpc(sess);
    propagate_errno(sess);
    return sess->req.result;
}

/* ---- recv() ----------------------------------------------------------- */

LONG bsd_recv(LONG fd __asm("d0"), APTR buf __asm("a0"), LONG len __asm("d1"),
              LONG flags __asm("d2"), struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    if (!sess || len <= 0) return (len == 0) ? 0 : -1;

    sess->req.opcode = BSDOP_RECV;
    sess->req.arglen = 8;
    w16(&sess->req.args[0], (UWORD)fd);
    w16(&sess->req.args[2], (UWORD)flags);
    w32(&sess->req.args[4], (ULONG)len);
    sess->req.indata = NULL; sess->req.inlen = 0;
    sess->req.outdata = buf;
    sess->req.outmax  = (ULONG)len;
    do_rpc(sess);
    propagate_errno(sess);
    return sess->req.result;
}

/* ---- gethostbyname() -------------------------------------------------- */

struct hostent *bsd_gethostbyname(STRPTR name __asm("a0"),
                                   struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    UBYTE namelen, i;
    UBYTE addr_buf[16]; /* up to 4 IPv4 addrs */
    if (!sess || !name) return NULL;

    namelen = 0;
    while (name[namelen] && namelen < 200) namelen++;

    sess->req.opcode = BSDOP_GETHOSTBYNAME;
    sess->req.arglen = 1 + namelen;
    sess->req.args[0] = namelen;
    for (i = 0; i < namelen; i++) sess->req.args[1 + i] = (UBYTE)name[i];
    sess->req.indata = NULL; sess->req.inlen = 0;
    sess->req.outdata = addr_buf;
    sess->req.outmax  = sizeof addr_buf;
    do_rpc(sess);
    propagate_errno(sess);

    if (sess->req.result <= 0) return NULL;

    /* Take the first address. */
    sess->haddr = ((ULONG)addr_buf[0] << 24) | ((ULONG)addr_buf[1] << 16)
                | ((ULONG)addr_buf[2] <<  8) |  (ULONG)addr_buf[3];
    for (i = 0; i < namelen; i++) sess->hname[i] = name[i];
    sess->hname[namelen] = 0;
    return &sess->hent;
}

/* ---- inet_ntoa() — local-only ----------------------------------------- */

STRPTR bsd_inet_ntoa(ULONG addr __asm("d0"), struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    BYTE  *p;
    UWORD  pos;
    UBYTE  bytes[4];
    UBYTE  i, v;

    if (!sess) return (STRPTR)"0.0.0.0";

    bytes[0] = (UBYTE)(addr >> 24);
    bytes[1] = (UBYTE)(addr >> 16);
    bytes[2] = (UBYTE)(addr >>  8);
    bytes[3] = (UBYTE)addr;

    p   = sess->ntoa_buf;
    pos = 0;
    for (i = 0; i < 4; i++) {
        v = bytes[i];
        if (v >= 100) { p[pos++] = '0' + v/100; v %= 100;
                        p[pos++] = '0' + v/10;  v %= 10; }
        else if (v >= 10) { p[pos++] = '0' + v/10; v %= 10; }
        p[pos++] = '0' + v;
        if (i < 3) p[pos++] = '.';
    }
    p[pos] = 0;
    return (STRPTR)p;
}

/* ---- inet_addr() — local-only ----------------------------------------- */

ULONG bsd_inet_addr(STRPTR s __asm("a0"), struct BsdBase *base __asm("a6"))
{
    ULONG result = 0, cur = 0;
    UBYTE parts = 0, c;
    (void)base;
    if (!s) return 0xFFFFFFFFUL;
    while ((c = (UBYTE)*s++) != 0) {
        if (c >= '0' && c <= '9') {
            cur = cur * 10 + (c - '0');
            if (cur > 255) return 0xFFFFFFFFUL;
        } else if (c == '.') {
            result = (result << 8) | (cur & 0xFF);
            cur = 0; parts++;
            if (parts > 3) return 0xFFFFFFFFUL;
        } else return 0xFFFFFFFFUL;
    }
    result = (result << 8) | (cur & 0xFF);
    parts++;
    if (parts != 4) return 0xFFFFFFFFUL;
    return result;
}

/* ---- shutdown() ------------------------------------------------------- */

LONG bsd_shutdown(LONG fd __asm("d0"), LONG how __asm("d1"),
                  struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    if (!sess) return -1;
    sess->req.opcode = BSDOP_SHUTDOWN;
    sess->req.arglen = 4;
    w16(&sess->req.args[0], (UWORD)fd);
    w16(&sess->req.args[2], (UWORD)how);
    sess->req.indata = NULL; sess->req.inlen = 0;
    sess->req.outdata = NULL; sess->req.outmax = 0;
    do_rpc(sess);
    propagate_errno(sess);
    return sess->req.result;
}

/* ---- ioctlsocket() ---------------------------------------------------- */

LONG bsd_ioctlsocket(LONG fd __asm("d0"), LONG request __asm("d1"),
                     APTR argp __asm("a0"), struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    ULONG arg;
    if (!sess) return -1;
    arg = argp ? *(ULONG *)argp : 0;
    sess->req.opcode = BSDOP_IOCTL;
    sess->req.arglen = 10;
    w16(&sess->req.args[0], (UWORD)fd);
    w32(&sess->req.args[2], (ULONG)request);
    w32(&sess->req.args[6], arg);
    sess->req.indata = NULL; sess->req.inlen = 0;
    sess->req.outdata = NULL; sess->req.outmax = 0;
    do_rpc(sess);
    propagate_errno(sess);
    /* For FIONREAD, the count comes back in result. */
    if (argp && (ULONG)request == 0x4004667fUL) *(ULONG *)argp = (ULONG)sess->req.result;
    return sess->req.result;
}

/* ---- waitselect() ----------------------------------------------------- */

LONG bsd_waitselect(LONG nfds __asm("d0"),
                    fd_set *rfds __asm("a0"), fd_set *wfds __asm("a1"),
                    fd_set *efds __asm("a2"), struct timeval *tv __asm("a3"),
                    ULONG *sigmask __asm("d1"), struct BsdBase *base __asm("a6"))
{
    struct ExecBase   *SysBase = base->SysBase;
    struct BsdSession *sess    = find_session(base);
    UBYTE  out_buf[12];
    ULONG  rm, wm, em, tv_sec, tv_usec;
    if (!sess) return -1;

    rm = rfds ? *rfds : 0;
    wm = wfds ? *wfds : 0;
    em = efds ? *efds : 0;
    if (tv) { tv_sec = (ULONG)tv->tv_sec; tv_usec = (ULONG)tv->tv_usec; }
    else    { tv_sec = 0xffffffffUL; tv_usec = 0; }

    sess->req.opcode = BSDOP_WAITSELECT;
    sess->req.arglen = 22;
    w16(&sess->req.args[0], (UWORD)nfds);
    w32(&sess->req.args[2], rm);
    w32(&sess->req.args[6], wm);
    w32(&sess->req.args[10], em);
    w32(&sess->req.args[14], tv_sec);
    w32(&sess->req.args[18], tv_usec);
    sess->req.indata = NULL; sess->req.inlen = 0;
    sess->req.outdata = out_buf; sess->req.outmax = sizeof out_buf;
    do_rpc(sess);
    propagate_errno(sess);

    if (sigmask) *sigmask = SetSignal(0UL, *sigmask) & *sigmask;
    if (sess->req.result < 0) return -1;
    if (rfds) *rfds = ((ULONG)out_buf[0]<<24)|((ULONG)out_buf[1]<<16)|((ULONG)out_buf[2]<<8)|out_buf[3];
    if (wfds) *wfds = ((ULONG)out_buf[4]<<24)|((ULONG)out_buf[5]<<16)|((ULONG)out_buf[6]<<8)|out_buf[7];
    if (efds) *efds = ((ULONG)out_buf[8]<<24)|((ULONG)out_buf[9]<<16)|((ULONG)out_buf[10]<<8)|out_buf[11];
    return sess->req.result;
}

/* ---- SocketBaseTagList ------------------------------------------------ */

LONG bsd_socketbasetaglist(APTR taglist __asm("a0"), struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    ULONG *ti = (ULONG *)taglist;
    if (!ti || !sess) return 0;
    while (1) {
        ULONG tag = ti[0], data = ti[1];
        ti += 2;
        if (tag == 0) break;
        if (tag == 1) continue;
        if (tag == 2) { ti = (ULONG *)(APTR)data; continue; }
        if (tag == 3) { ti += data * 2; continue; }
        /* SBTM_SETVAL(SBTC_ERRNOLONGPTR=24) = 0x80000031 */
        if (tag == 0x80000031UL && data) sess->errno_ptr = (LONG *)data;
        /* SBTM_SETREF variant = 0x80008031 */
        else if (tag == 0x80008031UL && data) sess->errno_ptr = *((LONG **)data);
        /* SBTM_SETVAL(SBTC_HERRNOLONGPTR=25) = 0x80000033 */
        else if (tag == 0x80000033UL && data) {
            sess->h_errno_ptr = (LONG *)data;
            *sess->h_errno_ptr = 0;
        }
        else if (tag == 0x80008033UL && data) {
            sess->h_errno_ptr = *((LONG **)data);
            if (sess->h_errno_ptr) *sess->h_errno_ptr = 0;
        }
    }
    return 0;
}

/* ---- bind() / listen() / accept() ------------------------------------- */

LONG bsd_bind(LONG fd __asm("d0"), APTR sa __asm("a0"), LONG addrlen __asm("d1"),
              struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    UWORD i;
    if (!sess) return -1;
    if (addrlen < 0 || addrlen > 64) addrlen = 16;
    sess->req.opcode = BSDOP_BIND;
    sess->req.arglen = 3 + (UWORD)addrlen;
    w16(&sess->req.args[0], (UWORD)fd);
    sess->req.args[2] = (UBYTE)addrlen;
    for (i = 0; i < (UWORD)addrlen; i++)
        sess->req.args[3 + i] = ((UBYTE *)sa)[i];
    sess->req.indata = NULL; sess->req.inlen = 0;
    sess->req.outdata = NULL; sess->req.outmax = 0;
    do_rpc(sess);
    propagate_errno(sess);
    return sess->req.result;
}

LONG bsd_listen(LONG fd __asm("d0"), LONG backlog __asm("d1"),
                struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    if (!sess) return -1;
    sess->req.opcode = BSDOP_LISTEN;
    sess->req.arglen = 4;
    w16(&sess->req.args[0], (UWORD)fd);
    w16(&sess->req.args[2], (UWORD)backlog);
    sess->req.indata = NULL; sess->req.inlen = 0;
    sess->req.outdata = NULL; sess->req.outmax = 0;
    do_rpc(sess);
    propagate_errno(sess);
    return sess->req.result;
}

LONG bsd_accept(LONG fd __asm("d0"), APTR sa __asm("a0"), LONG *al __asm("a1"),
                struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    UBYTE  out_buf[24];     /* alen(1) + sockaddr_in(16) */
    UBYTE  alen, i;
    if (!sess) return -1;
    sess->req.opcode = BSDOP_ACCEPT;
    sess->req.arglen = 2;
    w16(&sess->req.args[0], (UWORD)fd);
    sess->req.indata = NULL; sess->req.inlen = 0;
    sess->req.outdata = out_buf; sess->req.outmax = sizeof out_buf;
    do_rpc(sess);
    propagate_errno(sess);
    if (sess->req.result < 0) return -1;
    /* out_buf[0] = addrlen, out_buf[1..] = sockaddr bytes */
    alen = out_buf[0];
    if (sa && al) {
        LONG cap = *al;
        if (cap < 0) cap = 0;
        if (cap > (LONG)alen) cap = (LONG)alen;
        for (i = 0; i < (UBYTE)cap; i++) ((UBYTE *)sa)[i] = out_buf[1 + i];
        *al = (LONG)alen;
    }
    return sess->req.result;
}

/* ---- sendto() / recvfrom() ------------------------------------------- */

LONG bsd_sendto(LONG fd __asm("d0"), APTR buf __asm("a0"), LONG len __asm("d1"),
                LONG flags __asm("d2"), APTR sa __asm("a1"), LONG al __asm("d3"),
                struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    UWORD i;
    if (!sess || len <= 0) return (len == 0) ? 0 : -1;
    if (al < 0 || al > 64) al = 16;
    sess->req.opcode = BSDOP_SENDTO;
    sess->req.arglen = 5 + (UWORD)al;
    w16(&sess->req.args[0], (UWORD)fd);
    w16(&sess->req.args[2], (UWORD)flags);
    sess->req.args[4] = (UBYTE)al;
    for (i = 0; i < (UWORD)al; i++) sess->req.args[5 + i] = ((UBYTE *)sa)[i];
    sess->req.indata = buf;
    sess->req.inlen  = (ULONG)len;
    sess->req.outdata = NULL; sess->req.outmax = 0;
    do_rpc(sess);
    propagate_errno(sess);
    return sess->req.result;
}

LONG bsd_recvfrom(LONG fd __asm("d0"), APTR buf __asm("a0"), LONG len __asm("d1"),
                  LONG flags __asm("d2"), APTR sa __asm("a1"), LONG *al __asm("a2"),
                  struct BsdBase *base __asm("a6"))
{
    /* Pi returns: addrlen(1) sockaddr(16) data[len].  We need a temp
     * scratch buffer that fits the peer addr plus the data — allocate
     * caller's len+17 to be safe.  For the common case we copy in two
     * passes (peer addr extracted, data copied to caller's buf). */
    struct ExecBase   *SysBase = base->SysBase;
    struct BsdSession *sess    = find_session(base);
    UBYTE  hdr_buf[17];
    APTR   data_buf;
    UBYTE  alen;
    UWORD  i;
    if (!sess || len <= 0) return (len == 0) ? 0 : -1;

    /* For simplicity we ask Pi for the data into a scratch sized for hdr+data,
     * but our outdata is fixed.  Workaround: tell dispatcher about a separate
     * "hdr followed by caller buf" using a local stash + caller buf in one
     * contiguous read.  Easier path: allocate a single buffer the dispatcher
     * fills, then split. */
    data_buf = AllocVec((ULONG)len + 17, MEMF_PUBLIC);
    if (!data_buf) return -1;

    sess->req.opcode = BSDOP_RECVFROM;
    sess->req.arglen = 8;
    w16(&sess->req.args[0], (UWORD)fd);
    w16(&sess->req.args[2], (UWORD)flags);
    w32(&sess->req.args[4], (ULONG)len);
    sess->req.indata = NULL; sess->req.inlen = 0;
    sess->req.outdata = data_buf;
    sess->req.outmax  = (ULONG)len + 17;
    do_rpc(sess);
    propagate_errno(sess);

    if (sess->req.result < 0) {
        FreeVec(data_buf);
        return -1;
    }
    /* layout: [0]=alen, [1..16]=sockaddr, [17..]=data */
    alen = ((UBYTE *)data_buf)[0];
    for (i = 0; i < 17; i++) hdr_buf[i] = ((UBYTE *)data_buf)[i];
    for (i = 0; i < sess->req.result && i < len; i++)
        ((UBYTE *)buf)[i] = ((UBYTE *)data_buf)[17 + i];

    if (sa && al) {
        LONG cap = *al;
        if (cap < 0) cap = 0;
        if (cap > 16) cap = 16;
        for (i = 0; i < (UWORD)cap; i++) ((UBYTE *)sa)[i] = hdr_buf[1 + i];
        *al = (LONG)alen;
    }
    FreeVec(data_buf);
    return sess->req.result;
}

/* ---- getsockopt() / setsockopt() ------------------------------------- */

LONG bsd_setsockopt(LONG fd __asm("d0"), LONG level __asm("d1"), LONG optname __asm("d2"),
                    APTR optval __asm("a0"), LONG optlen __asm("d3"),
                    struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    if (!sess) return -1;
    if (optlen < 0 || optlen > 64) optlen = 4;
    sess->req.opcode = BSDOP_SETSOCKOPT;
    sess->req.arglen = 8;
    w16(&sess->req.args[0], (UWORD)fd);
    w16(&sess->req.args[2], (UWORD)level);
    w16(&sess->req.args[4], (UWORD)optname);
    w16(&sess->req.args[6], (UWORD)optlen);
    sess->req.indata = optval;
    sess->req.inlen  = (ULONG)optlen;
    sess->req.outdata = NULL; sess->req.outmax = 0;
    do_rpc(sess);
    propagate_errno(sess);
    return sess->req.result;
}

LONG bsd_getsockopt(LONG fd __asm("d0"), LONG level __asm("d1"), LONG optname __asm("d2"),
                    APTR optval __asm("a0"), LONG *optlen __asm("a1"),
                    struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    UBYTE  out_buf[68];     /* 2-byte length + up to 64 bytes optval */
    UWORD  n, i;
    LONG   maxlen;
    if (!sess) return -1;
    maxlen = optlen ? *optlen : 4;
    if (maxlen < 0 || maxlen > 64) maxlen = 64;
    sess->req.opcode = BSDOP_GETSOCKOPT;
    sess->req.arglen = 8;
    w16(&sess->req.args[0], (UWORD)fd);
    w16(&sess->req.args[2], (UWORD)level);
    w16(&sess->req.args[4], (UWORD)optname);
    w16(&sess->req.args[6], (UWORD)maxlen);
    sess->req.indata = NULL; sess->req.inlen = 0;
    sess->req.outdata = out_buf; sess->req.outmax = sizeof out_buf;
    do_rpc(sess);
    propagate_errno(sess);
    if (sess->req.result < 0) return -1;
    /* out_buf = optlen(2 BE) optval[optlen] */
    n = ((UWORD)out_buf[0] << 8) | out_buf[1];
    if (n > 64) n = 64;
    if (optval) {
        LONG cap = maxlen < (LONG)n ? maxlen : (LONG)n;
        for (i = 0; i < (UWORD)cap; i++) ((UBYTE *)optval)[i] = out_buf[2 + i];
    }
    if (optlen) *optlen = (LONG)n;
    return 0;
}

/* ---- getsockname() / getpeername() ----------------------------------- */

static LONG _sockname_rpc(struct BsdSession *sess, UBYTE opcode,
                          LONG fd, APTR sa, LONG *al)
{
    UBYTE out_buf[24];
    UBYTE alen, i;
    sess->req.opcode = opcode;
    sess->req.arglen = 2;
    w16(&sess->req.args[0], (UWORD)fd);
    sess->req.indata = NULL; sess->req.inlen = 0;
    sess->req.outdata = out_buf; sess->req.outmax = sizeof out_buf;
    do_rpc(sess);
    propagate_errno(sess);
    if (sess->req.result < 0) return -1;
    alen = out_buf[0];
    if (sa && al) {
        LONG cap = *al;
        if (cap < 0) cap = 0;
        if (cap > (LONG)alen) cap = (LONG)alen;
        for (i = 0; i < (UBYTE)cap; i++) ((UBYTE *)sa)[i] = out_buf[1 + i];
        *al = (LONG)alen;
    }
    return 0;
}

LONG bsd_getsockname(LONG fd __asm("d0"), APTR sa __asm("a0"), LONG *al __asm("a1"),
                     struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    if (!sess) return -1;
    return _sockname_rpc(sess, BSDOP_GETSOCKNAME, fd, sa, al);
}

LONG bsd_getpeername(LONG fd __asm("d0"), APTR sa __asm("a0"), LONG *al __asm("a1"),
                     struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    if (!sess) return -1;
    return _sockname_rpc(sess, BSDOP_GETPEERNAME, fd, sa, al);
}

void bsd_setsocketsignals(ULONG d0 __asm("d0"), ULONG d1 __asm("d1"),
                          ULONG d2 __asm("d2"), struct BsdBase *base __asm("a6"))
{ (void)d0; (void)d1; (void)d2; (void)base; }

LONG bsd_getdtablesize(struct BsdBase *base __asm("a6"))
{ (void)base; return 32; }

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

ULONG bsd_inet_lnaof(ULONG in __asm("d0"), struct BsdBase *base __asm("a6"))
{ (void)base; return in & 0xFF; }

ULONG bsd_inet_netof(ULONG in __asm("d0"), struct BsdBase *base __asm("a6"))
{ (void)base; return in >> 8; }

ULONG bsd_inet_makeaddr(ULONG net __asm("d0"), ULONG host __asm("d1"),
                        struct BsdBase *base __asm("a6"))
{ (void)base; return (net << 8) | (host & 0xFF); }

ULONG bsd_inet_network(STRPTR s __asm("a0"), struct BsdBase *base __asm("a6"))
{ return bsd_inet_addr(s, base); }

struct hostent *bsd_gethostbyaddr(APTR addr __asm("a0"), LONG len __asm("d0"),
                                   LONG type __asm("d1"),
                                   struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    UBYTE  i;
    if (!sess || !addr || len < 4) return NULL;
    sess->req.opcode = BSDOP_GETHOSTBYADDR;
    sess->req.arglen = 1 + (UWORD)len + 2;
    sess->req.args[0] = (UBYTE)len;
    for (i = 0; i < (UBYTE)len; i++) sess->req.args[1 + i] = ((UBYTE *)addr)[i];
    w16(&sess->req.args[1 + len], (UWORD)type);
    sess->req.indata = NULL; sess->req.inlen = 0;
    sess->req.outdata = sess->hname; sess->req.outmax = sizeof sess->hname - 1;
    do_rpc(sess);
    propagate_errno(sess);
    if (sess->req.result < 0) return NULL;
    /* sess->req.outlen is the actual hostname length written to sess->hname */
    if (sess->req.outlen >= sizeof sess->hname)
        sess->req.outlen = sizeof sess->hname - 1;
    sess->hname[sess->req.outlen] = 0;
    /* Cache the queried IP in the hostent. */
    if (len >= 4)
        sess->haddr = ((ULONG)((UBYTE *)addr)[0] << 24) |
                      ((ULONG)((UBYTE *)addr)[1] << 16) |
                      ((ULONG)((UBYTE *)addr)[2] <<  8) |
                       (ULONG)((UBYTE *)addr)[3];
    return &sess->hent;
}

struct netent *bsd_getnetbyname(STRPTR a0 __asm("a0"), struct BsdBase *base __asm("a6"))
{ (void)a0; (void)base; return NULL; }

struct netent *bsd_getnetbyaddr(ULONG d0 __asm("d0"), LONG d1 __asm("d1"),
                                 struct BsdBase *base __asm("a6"))
{ (void)d0; (void)d1; (void)base; return NULL; }

struct servent *bsd_getservbyname(STRPTR a0 __asm("a0"), STRPTR a1 __asm("a1"),
                                   struct BsdBase *base __asm("a6"))
{ (void)a0; (void)a1; (void)base; return NULL; }

struct servent *bsd_getservbyport(LONG d0 __asm("d0"), STRPTR a0 __asm("a0"),
                                   struct BsdBase *base __asm("a6"))
{ (void)d0; (void)a0; (void)base; return NULL; }

/* IANA-standardised protocol numbers — these don't change, so we serve
 * them locally without a Pi round-trip.  ping needs "icmp" (=1) to even
 * start. */
static const struct { const char *name; int proto; } _proto_table[] = {
    { "ip",    0   }, { "icmp",  1   }, { "igmp",  2   },
    { "tcp",   6   }, { "udp",   17  }, { "raw",   255 },
    { NULL,    0   }
};

static struct protoent *_fill_pent(struct BsdSession *sess,
                                   const char *name, int proto)
{
    UBYTE i;
    for (i = 0; name[i] && i < 15; i++) sess->pent_name[i] = name[i];
    sess->pent_name[i] = 0;
    sess->pent.p_proto = proto;
    return &sess->pent;
}

struct protoent *bsd_getprotobyname(STRPTR a0 __asm("a0"),
                                     struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    UWORD i, j;
    if (!sess || !a0) return NULL;
    for (i = 0; _proto_table[i].name; i++) {
        const char *p = _proto_table[i].name;
        const char *q = (const char *)a0;
        j = 0;
        while (p[j] && q[j] && p[j] == q[j]) j++;
        if (!p[j] && !q[j])
            return _fill_pent(sess, _proto_table[i].name, _proto_table[i].proto);
    }
    return NULL;
}

struct protoent *bsd_getprotobynumber(LONG d0 __asm("d0"),
                                       struct BsdBase *base __asm("a6"))
{
    struct BsdSession *sess = find_session(base);
    UWORD i;
    if (!sess) return NULL;
    for (i = 0; _proto_table[i].name; i++) {
        if (_proto_table[i].proto == (int)d0)
            return _fill_pent(sess, _proto_table[i].name, _proto_table[i].proto);
    }
    return NULL;
}

void bsd_vsyslog(LONG d0 __asm("d0"), STRPTR a0 __asm("a0"), APTR a1 __asm("a1"),
                 struct BsdBase *base __asm("a6"))
{ (void)d0; (void)a0; (void)a1; (void)base; }

LONG bsd_dup2socket(LONG d0 __asm("d0"), LONG d1 __asm("d1"),
                    struct BsdBase *base __asm("a6"))
{ (void)d0; (void)d1; (void)base; return -1; }

LONG bsd_sendmsg(LONG d0 __asm("d0"), APTR a0 __asm("a0"), LONG d1 __asm("d1"),
                 struct BsdBase *base __asm("a6"))
{ (void)d0; (void)a0; (void)d1; (void)base; return -1; }

LONG bsd_recvmsg(LONG d0 __asm("d0"), APTR a0 __asm("a0"), LONG d1 __asm("d1"),
                 struct BsdBase *base __asm("a6"))
{ (void)d0; (void)a0; (void)d1; (void)base; return -1; }

LONG bsd_gethostname(APTR buf __asm("a0"), LONG buflen __asm("d0"),
                     struct BsdBase *base __asm("a6"))
{ (void)buf; (void)buflen; (void)base; return -1; }

ULONG bsd_gethostid(struct BsdBase *base __asm("a6"))
{ (void)base; return 0; }

ULONG bsd_getsocketevents(APTR a0 __asm("a0"), struct BsdBase *base __asm("a6"))
{ (void)a0; (void)base; return 0; }
