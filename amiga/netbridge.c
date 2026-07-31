/*
 * netbridge.c - NetBridge: a314bsd network control panel (GadTools)
 *
 * A small "Roadie for a314bsd": shows whether the bsdsocket proxy is
 * accepting new connections, with Connect / Disconnect / Refresh, plus a
 * host field for Ping and a Net Status report.  Talks the "bsdctl" A314
 * service (see pi/bsdctl.py) directly via a314.device — does NOT need
 * bsdsocket.library to be up.
 *
 *   Disconnect -> BSDCTL_PAUSE  (block new connections; live ones keep working)
 *   Connect    -> BSDCTL_RESUME (allow new connections)
 *   Refresh    -> BSDCTL_QUERY  (re-read current state)
 *   Net Status -> BSDCTL_STATUS (Pi link report, shown in a requester)
 *   Ping       -> BSDCTL_PING   (ping the Host field via the Pi)
 *
 * Build:  make netbridge
 */

#include <exec/types.h>
#include <exec/io.h>
#include <exec/ports.h>
#include <intuition/intuition.h>
#include <intuition/gadgetclass.h>
#include <libraries/gadtools.h>
#include <proto/exec.h>
#include <proto/intuition.h>
#include <proto/gadtools.h>
#include <proto/graphics.h>

#include "a314.h"

unsigned long __stack = 16000;

/* bsdctl protocol — must match amiga/bsdnet.c and pi/bsdctl.py */
#define BSDCTL_QUERY   0x01
#define BSDCTL_PAUSE   0x02
#define BSDCTL_RESUME  0x03
#define BSDCTL_STATUS  0x04
#define BSDCTL_PING    0x05
#define BSDCTL_ERROR   0x00
#define BSDCTL_RUNNING 0x01
#define BSDCTL_PAUSED  0x02
#define BSDCTL_OK      0x03

struct IntuitionBase *IntuitionBase = NULL;
struct GfxBase       *GfxBase        = NULL;
struct Library       *GadToolsBase   = NULL;

/* Gadget IDs */
#define GID_DISCONNECT 1
#define GID_CONNECT    2
#define GID_REFRESH    3
#define GID_PING       4
#define GID_STATUS     5
#define GID_HOST       6

struct Gui {
    struct Screen  *scr;
    APTR            vi;
    struct Window  *win;
    struct Gadget  *glist;
    struct Gadget  *gStatus;
    struct Gadget  *gHost;
};

/* ------------------------------------------------------------------------
 * bsdctl comms: send cmd (+ optional ASCII arg), read the reply.
 *   reply wire format: status(1) textlen(1) text[textlen]
 * Returns the status byte, or -1 on any failure (a314.device missing,
 * service not registered, Pi down, ...).  If outText != NULL the reply text
 * is copied there (NUL-terminated, clipped to outMax).
 * ---------------------------------------------------------------------- */
static int bsdctl(UBYTE cmd, CONST_STRPTR arg, char *outText, int outMax)
{
    struct MsgPort        *port;
    struct A314_IORequest *ior;
    UBYTE                  wbuf[160];
    UBYTE                  rbuf[210];
    int                    wlen   = 1;
    int                    result = -1;

    if (outText && outMax > 0) outText[0] = 0;

    port = CreateMsgPort();
    if (!port) return -1;
    ior = (struct A314_IORequest *)CreateIORequest(port, sizeof(struct A314_IORequest));
    if (!ior) { DeleteMsgPort(port); return -1; }

    if (OpenDevice(A314_NAME, 0, (struct IORequest *)ior, 0) != 0) {
        DeleteIORequest((struct IORequest *)ior);
        DeleteMsgPort(port);
        return -1;
    }

    wbuf[0] = cmd;
    if (arg) {
        int i = 0;
        while (arg[i] && wlen < (int)sizeof(wbuf))
            wbuf[wlen++] = (UBYTE)arg[i++];
    }

    /* a314.device rejects A314_CONNECT for a socket ID it just closed, so use
     * a monotonic per-connect ID (seeded from the task ptr) rather than a
     * fixed FindTask value — otherwise every 2nd+ connect (Refresh) fails. */
    {
        static ULONG s_sockid = 0;
        if (s_sockid == 0) s_sockid = (ULONG)FindTask(NULL);
        ior->a314_Socket = s_sockid++;
    }
    ior->a314_Buffer = (STRPTR)"bsdctl";
    ior->a314_Length = 6;
    ior->a314_Request.io_Command = A314_CONNECT;
    if (DoIO((struct IORequest *)ior) == A314_CONNECT_OK) {
        ior->a314_Request.io_Command = A314_WRITE;
        ior->a314_Buffer = (STRPTR)wbuf;
        ior->a314_Length = wlen;
        if (DoIO((struct IORequest *)ior) == A314_WRITE_OK) {
            ior->a314_Request.io_Command = A314_READ;
            ior->a314_Buffer = (STRPTR)rbuf;
            ior->a314_Length = sizeof(rbuf);
            if (DoIO((struct IORequest *)ior) == A314_READ_OK && ior->a314_Length >= 2) {
                int n    = ior->a314_Length;
                int tlen = rbuf[1];
                result   = rbuf[0];
                if (tlen > n - 2) tlen = n - 2;
                if (outText && outMax > 0) {
                    int c = tlen;
                    if (c > outMax - 1) c = outMax - 1;
                    CopyMem(rbuf + 2, outText, c);
                    outText[c] = 0;
                }
            }
        }
        ior->a314_Request.io_Command = A314_EOS;
        DoIO((struct IORequest *)ior);
    }

    CloseDevice((struct IORequest *)ior);
    DeleteIORequest((struct IORequest *)ior);
    DeleteMsgPort(port);
    return result;
}

/* Pop up a requester with a (possibly multi-line) body. */
static void report(struct Gui *g, CONST_STRPTR title, CONST_STRPTR body)
{
    struct EasyStruct es;
    CONST_STRPTR      bp = body;

    es.es_StructSize   = sizeof(es);
    es.es_Flags        = 0;
    es.es_Title        = (STRPTR)title;
    es.es_TextFormat   = (STRPTR)"%s";     /* body via arg -> no %-parsing */
    es.es_GadgetFormat = (STRPTR)"OK";
    EasyRequestArgs(g->win, &es, NULL, (APTR)&bp);
}

/* Update the status text gadget from a bsdctl response byte. */
static void showStatus(struct Gui *g, int rsp)
{
    CONST_STRPTR s;
    switch (rsp) {
    case BSDCTL_RUNNING: s = "Network: ONLINE  (accepting connections)"; break;
    case BSDCTL_PAUSED:  s = "Network: OFFLINE (new connections blocked)"; break;
    case BSDCTL_OK:      s = "Network: OK"; break;
    default:             s = "bsdctl not reachable - is a314d / bsdctl running?"; break;
    }
    if (g->gStatus)
        GT_SetGadgetAttrs(g->gStatus, g->win, NULL, (ULONG)GTTX_Text, (ULONG)s, TAG_END);
}

/* Read the Host string gadget into buf. */
static void getHost(struct Gui *g, char *buf, int max)
{
    STRPTR s = NULL;
    buf[0] = 0;
    GT_GetGadgetAttrs(g->gHost, g->win, NULL, (ULONG)GTST_String, (ULONG)&s, TAG_END);
    if (s) {
        int i = 0;
        while (s[i] && i < max - 1) { buf[i] = s[i]; i++; }
        buf[i] = 0;
    }
}

static void doPing(struct Gui *g)
{
    char host[128];
    char text[210];
    int  r;

    getHost(g, host, sizeof(host));
    if (host[0] == 0) {
        report(g, (CONST_STRPTR)"Ping", (CONST_STRPTR)"Enter a host or IP in the Host field first.");
        return;
    }
    showStatus(g, BSDCTL_OK);   /* transient hint while the ping runs */
    GT_SetGadgetAttrs(g->gStatus, g->win, NULL,
                      (ULONG)GTTX_Text, (ULONG)"Pinging...", TAG_END);

    r = bsdctl(BSDCTL_PING, (CONST_STRPTR)host, text, sizeof(text));
    if (r < 0)
        report(g, (CONST_STRPTR)"Ping", (CONST_STRPTR)"bsdctl not reachable - is a314d / bsdctl running?");
    else
        report(g, (CONST_STRPTR)"Ping", (CONST_STRPTR)text);

    showStatus(g, bsdctl(BSDCTL_QUERY, NULL, NULL, 0));   /* restore status line */
}

static void doNetStatus(struct Gui *g)
{
    char text[210];
    int  r = bsdctl(BSDCTL_STATUS, NULL, text, sizeof(text));
    if (r < 0)
        report(g, (CONST_STRPTR)"Net Status", (CONST_STRPTR)"bsdctl not reachable - is a314d / bsdctl running?");
    else
        report(g, (CONST_STRPTR)"Net Status", (CONST_STRPTR)text);
}

/* ------------------------------------------------------------------------
 * GUI
 * ---------------------------------------------------------------------- */
static BOOL createGadgets(struct Gui *g)
{
    struct NewGadget ng;
    struct Gadget   *gad;
    /* GadTools gadget coords are relative to the window's top-left INCLUDING
     * the title bar, so offset everything below the border. (RKM idiom.) */
    WORD tb = g->scr->WBorTop + g->scr->Font->ta_YSize + 1;  /* below title bar */
    WORD lb = g->scr->WBorLeft;

    gad = CreateContext(&g->glist);
    if (!gad) return FALSE;

    ng.ng_VisualInfo = g->vi;
    ng.ng_TextAttr   = g->scr->Font;
    ng.ng_Flags      = 0;

    /* Status text (read-only) */
    ng.ng_LeftEdge = lb + 8; ng.ng_TopEdge = tb + 4;
    ng.ng_Width    = 360; ng.ng_Height = 14;   /* fit the longest status line */
    ng.ng_GadgetText = NULL;
    ng.ng_GadgetID   = 0;
    gad = g->gStatus = CreateGadget(TEXT_KIND, gad, &ng,
              (ULONG)GTTX_Text, (ULONG)"Querying...",
              (ULONG)GTTX_Border, TRUE, TAG_END);

    /* Host string gadget (ping target) */
    ng.ng_LeftEdge = lb + 48; ng.ng_TopEdge = tb + 24;
    ng.ng_Width    = 320; ng.ng_Height = 14;
    ng.ng_GadgetText = (STRPTR)"Host";
    ng.ng_Flags      = PLACETEXT_LEFT;
    ng.ng_GadgetID   = GID_HOST;
    gad = g->gHost = CreateGadget(STRING_KIND, gad, &ng,
              (ULONG)GTST_String, (ULONG)"1.1.1.1",
              (ULONG)GTST_MaxChars, 120, TAG_END);
    ng.ng_Flags = 0;

    /* Buttons row 1 */
    ng.ng_TopEdge = tb + 46; ng.ng_Width = 100; ng.ng_Height = 16;
    ng.ng_LeftEdge = lb + 8;   ng.ng_GadgetText = (STRPTR)"_Disconnect";
    ng.ng_GadgetID = GID_DISCONNECT;
    gad = CreateGadget(BUTTON_KIND, gad, &ng, (ULONG)GT_Underscore, '_', TAG_END);

    ng.ng_LeftEdge = lb + 140; ng.ng_GadgetText = (STRPTR)"_Connect";
    ng.ng_GadgetID = GID_CONNECT;
    gad = CreateGadget(BUTTON_KIND, gad, &ng, (ULONG)GT_Underscore, '_', TAG_END);

    ng.ng_LeftEdge = lb + 272; ng.ng_GadgetText = (STRPTR)"_Refresh";
    ng.ng_GadgetID = GID_REFRESH;
    gad = CreateGadget(BUTTON_KIND, gad, &ng, (ULONG)GT_Underscore, '_', TAG_END);

    /* Buttons row 2 */
    ng.ng_TopEdge = tb + 68; ng.ng_Width = 100;
    ng.ng_LeftEdge = lb + 8;   ng.ng_GadgetText = (STRPTR)"_Ping";
    ng.ng_GadgetID = GID_PING;
    gad = CreateGadget(BUTTON_KIND, gad, &ng, (ULONG)GT_Underscore, '_', TAG_END);

    ng.ng_LeftEdge = lb + 140; ng.ng_Width = 130; ng.ng_GadgetText = (STRPTR)"_Net Status";
    ng.ng_GadgetID = GID_STATUS;
    gad = CreateGadget(BUTTON_KIND, gad, &ng, (ULONG)GT_Underscore, '_', TAG_END);

    return (gad != NULL);
}

static BOOL openGui(struct Gui *g)
{
    g->scr = LockPubScreen(NULL);
    if (!g->scr) return FALSE;
    g->vi = GetVisualInfo(g->scr, TAG_END);
    if (!g->vi) return FALSE;
    if (!createGadgets(g)) return FALSE;

    g->win = OpenWindowTags(NULL,
        (ULONG)WA_Title,      (ULONG)"NetBridge",
        (ULONG)WA_Left,       40, (ULONG)WA_Top, 40,
        (ULONG)WA_InnerWidth, 380, (ULONG)WA_InnerHeight, 90,
        (ULONG)WA_Flags,      WFLG_DRAGBAR | WFLG_DEPTHGADGET |
                              WFLG_CLOSEGADGET | WFLG_ACTIVATE,
        (ULONG)WA_IDCMP,      IDCMP_CLOSEWINDOW | IDCMP_REFRESHWINDOW | BUTTONIDCMP,
        (ULONG)WA_Gadgets,    (ULONG)g->glist,
        (ULONG)WA_PubScreen,  (ULONG)g->scr,
        TAG_END);
    if (!g->win) return FALSE;

    GT_RefreshWindow(g->win, NULL);
    showStatus(g, bsdctl(BSDCTL_QUERY, NULL, NULL, 0));
    return TRUE;
}

static void closeGui(struct Gui *g)
{
    if (g->win)   CloseWindow(g->win);
    if (g->glist) FreeGadgets(g->glist);
    if (g->vi)    FreeVisualInfo(g->vi);
    if (g->scr)   UnlockPubScreen(NULL, g->scr);
}

static void eventLoop(struct Gui *g)
{
    struct IntuiMessage *imsg;
    BOOL running = TRUE;

    while (running) {
        WaitPort(g->win->UserPort);
        while ((imsg = GT_GetIMsg(g->win->UserPort))) {
            ULONG          cls  = imsg->Class;
            struct Gadget *gad  = (struct Gadget *)imsg->IAddress;
            GT_ReplyIMsg(imsg);

            switch (cls) {
            case IDCMP_CLOSEWINDOW:
                running = FALSE;
                break;
            case IDCMP_GADGETUP:
                switch (gad->GadgetID) {
                case GID_DISCONNECT: showStatus(g, bsdctl(BSDCTL_PAUSE,  NULL, NULL, 0)); break;
                case GID_CONNECT:    showStatus(g, bsdctl(BSDCTL_RESUME, NULL, NULL, 0)); break;
                case GID_REFRESH:    showStatus(g, bsdctl(BSDCTL_QUERY,  NULL, NULL, 0)); break;
                case GID_PING:       doPing(g);      break;
                case GID_STATUS:     doNetStatus(g); break;
                }
                break;
            case IDCMP_REFRESHWINDOW:
                GT_BeginRefresh(g->win);
                GT_EndRefresh(g->win, TRUE);
                break;
            }
        }
    }
}

int main(void)
{
    struct Gui g = {0};

    IntuitionBase = (struct IntuitionBase *)OpenLibrary((STRPTR)"intuition.library", 37);
    GfxBase       = (struct GfxBase *)OpenLibrary((STRPTR)"graphics.library", 37);
    GadToolsBase  = OpenLibrary((STRPTR)"gadtools.library", 37);

    if (IntuitionBase && GfxBase && GadToolsBase && openGui(&g))
        eventLoop(&g);

    closeGui(&g);
    if (GadToolsBase)  CloseLibrary(GadToolsBase);
    if (GfxBase)       CloseLibrary((struct Library *)GfxBase);
    if (IntuitionBase) CloseLibrary((struct Library *)IntuitionBase);
    return 0;
}
