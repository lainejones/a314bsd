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
 * Every action is on a button (plain-key shortcut = the underlined letter),
 * in the Network menu (Amiga-key shortcut) and Project has About / Quit.
 * NetBridge has no settings (no tooltypes, no prefs file), so no Settings
 * menu; the window is a fixed size, so no Snapshot either.
 *
 * Layout follows the window font: the screen font, or Topaz 8 when the
 * screen font would make the window too big (it must fit 640x200 with
 * Topaz 8 and is never wider than 600).
 *
 * Build:  make netbridge
 */

#include <exec/types.h>
#include <exec/io.h>
#include <exec/ports.h>
#include <intuition/intuition.h>
#include <intuition/gadgetclass.h>
#include <libraries/gadtools.h>
#include <graphics/text.h>
#include <graphics/rastport.h>
#include <proto/exec.h>
#include <proto/intuition.h>
#include <proto/gadtools.h>
#include <proto/graphics.h>

#include "a314.h"
#include "amigui.h"

#define NBR_NAME    "NetBridge"
#define NBR_VERSION "1.1"

unsigned long __stack = 16000;
static const char vers[] = "$VER: " NBR_NAME " " NBR_VERSION " (30.10.2026)";

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

#define NOT_REACHABLE "bsdctl not reachable - is a314d / bsdctl running?"

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

/* Menu item ids (GTMENUITEM_USERDATA) */
enum { MN_ABOUT = 1, MN_QUIT, MN_CONNECT, MN_DISCONNECT, MN_REFRESH, MN_PING, MN_NETSTATUS };

static struct NewMenu menu_def[] = {
    {NM_TITLE, (STRPTR)"Project",       NULL,         0, 0, NULL},
    {NM_ITEM,  (STRPTR)"About...",      (STRPTR)"?",  0, 0, (APTR)MN_ABOUT},
    {NM_ITEM,  NM_BARLABEL,             NULL,         0, 0, NULL},
    {NM_ITEM,  (STRPTR)"Quit",          (STRPTR)"Q",  0, 0, (APTR)MN_QUIT},
    {NM_TITLE, (STRPTR)"Network",       NULL,         0, 0, NULL},
    {NM_ITEM,  (STRPTR)"Connect",       (STRPTR)"O",  0, 0, (APTR)MN_CONNECT},
    {NM_ITEM,  (STRPTR)"Disconnect",    (STRPTR)"D",  0, 0, (APTR)MN_DISCONNECT},
    {NM_ITEM,  (STRPTR)"Refresh",       (STRPTR)"R",  0, 0, (APTR)MN_REFRESH},
    {NM_ITEM,  NM_BARLABEL,             NULL,         0, 0, NULL},
    {NM_ITEM,  (STRPTR)"Ping host...",  (STRPTR)"P",  0, 0, (APTR)MN_PING},
    {NM_ITEM,  (STRPTR)"Net Status...", (STRPTR)"N",  0, 0, (APTR)MN_NETSTATUS},
    {NM_END,   NULL,                    NULL,         0, 0, NULL}};

/* Every text the status line can show: the gadget is sized to the longest. */
static const char *status_texts[] = {
    "Network: ONLINE  (accepting connections)",
    "Network: OFFLINE (new connections blocked)",
    "Network: OK",
    "bsdctl not reachable (a314d running?)",
    "Querying...",
    "Pinging...",
    NULL};

static struct TextAttr topaz8 = {(STRPTR)"topaz.font", 8, FS_NORMAL, FPF_ROMFONT};

#define M   8           /* margin around the gadgets */
#define GAP 8           /* between buttons */
#define MAXW 600        /* never wider than a classic window */

struct Gui {
    struct Screen   *scr;
    APTR             vi;
    struct Window   *win;
    struct Gadget   *glist;
    struct Gadget   *gStatus;
    struct Gadget   *gHost;
    struct Menu     *menu;
    struct TextAttr  ta;        /* gadget font: screen font or Topaz 8 */
    struct TextFont *font;
    struct RastPort  rp;        /* for measuring text in that font */
    WORD             iw, ih;    /* inner size the layout needs */
    BOOL             quit;
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

static void setStatusText(struct Gui *g, CONST_STRPTR s)
{
    if (g->gStatus)
        GT_SetGadgetAttrs(g->gStatus, g->win, NULL, (ULONG)GTTX_Text, (ULONG)s, TAG_END);
}

/* Update the status text gadget from a bsdctl response byte. */
static void showStatus(struct Gui *g, int rsp)
{
    CONST_STRPTR s;
    switch (rsp) {
    case BSDCTL_RUNNING: s = (CONST_STRPTR)status_texts[0]; break;
    case BSDCTL_PAUSED:  s = (CONST_STRPTR)status_texts[1]; break;
    case BSDCTL_OK:      s = (CONST_STRPTR)status_texts[2]; break;
    default:             s = (CONST_STRPTR)status_texts[3]; break;
    }
    setStatusText(g, s);
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
    setStatusText(g, (CONST_STRPTR)"Pinging...");   /* transient hint while the ping runs */

    r = bsdctl(BSDCTL_PING, (CONST_STRPTR)host, text, sizeof(text));
    if (r < 0)
        report(g, (CONST_STRPTR)"Ping", (CONST_STRPTR)NOT_REACHABLE);
    else
        report(g, (CONST_STRPTR)"Ping", (CONST_STRPTR)text);

    showStatus(g, bsdctl(BSDCTL_QUERY, NULL, NULL, 0));   /* restore status line */
}

static void doNetStatus(struct Gui *g)
{
    char text[210];
    int  r = bsdctl(BSDCTL_STATUS, NULL, text, sizeof(text));
    if (r < 0)
        report(g, (CONST_STRPTR)"Net Status", (CONST_STRPTR)NOT_REACHABLE);
    else
        report(g, (CONST_STRPTR)"Net Status", (CONST_STRPTR)text);
}

static void doAbout(struct Gui *g)
{
    amg_about(g->win, NBR_NAME, NBR_VERSION,
              "Network control panel for a314bsd, the\n"
              "bsdsocket.library proxy over the A314.\n\n"
              "Licence: GPL-3.0");
}

/* The one place every action goes: buttons, keys and menus. */
static void doAction(struct Gui *g, int id)
{
    switch (id) {
    case GID_DISCONNECT: showStatus(g, bsdctl(BSDCTL_PAUSE,  NULL, NULL, 0)); break;
    case GID_CONNECT:    showStatus(g, bsdctl(BSDCTL_RESUME, NULL, NULL, 0)); break;
    case GID_REFRESH:    showStatus(g, bsdctl(BSDCTL_QUERY,  NULL, NULL, 0)); break;
    case GID_PING:       doPing(g);      break;
    case GID_STATUS:     doNetStatus(g); break;
    }
}

static void doMenu(struct Gui *g, ULONG id)
{
    switch (id) {
    case MN_ABOUT:      doAbout(g);                  break;
    case MN_QUIT:       g->quit = TRUE;              break;
    case MN_CONNECT:    doAction(g, GID_CONNECT);    break;
    case MN_DISCONNECT: doAction(g, GID_DISCONNECT); break;
    case MN_REFRESH:    doAction(g, GID_REFRESH);    break;
    case MN_PING:       doAction(g, GID_PING);       break;
    case MN_NETSTATUS:  doAction(g, GID_STATUS);     break;
    }
}

/* ------------------------------------------------------------------------
 * GUI
 * ---------------------------------------------------------------------- */

/* Pixel width of s in the gadget font, '_' (underscore marker) skipped. */
static int tlen(struct Gui *g, const char *s)
{
    char buf[80];
    int  n = 0;
    while (*s && n < (int)sizeof(buf)) {
        if (*s != '_') buf[n++] = *s;
        s++;
    }
    return TextLength(&g->rp, (STRPTR)buf, n);
}

static const char *btn_labels[] = {"_Disconnect", "_Connect", "_Refresh", "_Ping", "_Net Status", NULL};

/* Work out the inner size for the current font: g->iw, g->ih. */
static void measure(struct Gui *g, WORD *bw)
{
    int fh = g->font->tf_YSize;
    int w, i, need;

    *bw = 0;
    for (i = 0; btn_labels[i]; i++) {
        w = tlen(g, btn_labels[i]) + 16;
        if (w > *bw) *bw = w;
    }
    need = 3 * *bw + 2 * GAP;                     /* the 3-button row */
    for (i = 0; status_texts[i]; i++) {
        w = tlen(g, status_texts[i]) + 12;         /* + the recessed border */
        if (w > need) need = w;
    }
    w = tlen(g, "Host") + 8 + 20 * g->font->tf_XSize;   /* room for an address */
    if (w > need) need = w;

    g->iw = need + 2 * M;           /* openGui caps it at MAXW */
    /* status, host, button row 1, button row 2 */
    g->ih = 4 + (fh + 6) + 6 + (fh + 6) + 8 + (fh + 6) + 6 + (fh + 6) + 4;
}

static BOOL createGadgets(struct Gui *g, WORD bw)
{
    struct NewGadget ng;
    struct Gadget   *gad;
    /* GadTools gadget coords are relative to the window's top-left INCLUDING
     * the title bar, so offset everything below the border. (RKM idiom.) */
    WORD tb = g->scr->WBorTop + g->scr->Font->ta_YSize + 1;  /* below title bar */
    WORD lb = g->scr->WBorLeft;
    WORD fh = g->font->tf_YSize;
    WORD rh = fh + 6;                       /* gadget row height */
    WORD cw = g->iw - 2 * M;                /* content width */
    WORD hl = tlen(g, "Host") + 8;          /* Host label + gap */
    WORD y;

    /* spread the button columns over the content width */
    if (3 * bw + 2 * GAP < cw) bw = (cw - 2 * GAP) / 3;

    gad = CreateContext(&g->glist);
    if (!gad) return FALSE;

    ng.ng_VisualInfo = g->vi;
    ng.ng_TextAttr   = &g->ta;
    ng.ng_Flags      = 0;
    ng.ng_UserData   = NULL;

    /* Status text (read-only); clipped so it never draws past its edge */
    y = tb + 4;
    ng.ng_LeftEdge = lb + M; ng.ng_TopEdge = y;
    ng.ng_Width    = cw;     ng.ng_Height  = rh;
    ng.ng_GadgetText = NULL;
    ng.ng_GadgetID   = 0;
    gad = g->gStatus = CreateGadget(TEXT_KIND, gad, &ng,
              (ULONG)GTTX_Text, (ULONG)"Querying...",
              (ULONG)GTTX_Border, TRUE,
              (ULONG)GTTX_Clipped, TRUE, TAG_END);

    /* Host string gadget (ping target) */
    y += rh + 6;
    ng.ng_LeftEdge = lb + M + hl; ng.ng_TopEdge = y;
    ng.ng_Width    = cw - hl;     ng.ng_Height  = rh;
    ng.ng_GadgetText = (STRPTR)"Host";
    ng.ng_Flags      = PLACETEXT_LEFT;
    ng.ng_GadgetID   = GID_HOST;
    gad = g->gHost = CreateGadget(STRING_KIND, gad, &ng,
              (ULONG)GTST_String, (ULONG)"1.1.1.1",
              (ULONG)GTST_MaxChars, 120, TAG_END);
    ng.ng_Flags = 0;

    /* Buttons row 1 */
    y += rh + 8;
    ng.ng_TopEdge = y; ng.ng_Width = bw; ng.ng_Height = rh;
    ng.ng_LeftEdge = lb + M;                ng.ng_GadgetText = (STRPTR)"_Disconnect";
    ng.ng_GadgetID = GID_DISCONNECT;
    gad = CreateGadget(BUTTON_KIND, gad, &ng, (ULONG)GT_Underscore, '_', TAG_END);

    ng.ng_LeftEdge = lb + M + bw + GAP;     ng.ng_GadgetText = (STRPTR)"_Connect";
    ng.ng_GadgetID = GID_CONNECT;
    gad = CreateGadget(BUTTON_KIND, gad, &ng, (ULONG)GT_Underscore, '_', TAG_END);

    ng.ng_LeftEdge = lb + M + 2 * (bw + GAP); ng.ng_GadgetText = (STRPTR)"_Refresh";
    ng.ng_GadgetID = GID_REFRESH;
    gad = CreateGadget(BUTTON_KIND, gad, &ng, (ULONG)GT_Underscore, '_', TAG_END);

    /* Buttons row 2 */
    y += rh + 6;
    ng.ng_TopEdge = y;
    ng.ng_LeftEdge = lb + M;                ng.ng_GadgetText = (STRPTR)"_Ping";
    ng.ng_GadgetID = GID_PING;
    gad = CreateGadget(BUTTON_KIND, gad, &ng, (ULONG)GT_Underscore, '_', TAG_END);

    ng.ng_LeftEdge = lb + M + bw + GAP;     ng.ng_GadgetText = (STRPTR)"_Net Status";
    ng.ng_GadgetID = GID_STATUS;
    gad = CreateGadget(BUTTON_KIND, gad, &ng, (ULONG)GT_Underscore, '_', TAG_END);

    return (gad != NULL);
}

static BOOL openFont(struct Gui *g, struct TextAttr *ta)
{
    if (g->font) { CloseFont(g->font); g->font = NULL; }
    g->ta   = *ta;
    g->font = OpenFont(&g->ta);
    if (!g->font) return FALSE;
    InitRastPort(&g->rp);
    SetFont(&g->rp, g->font);
    return TRUE;
}

static BOOL openGui(struct Gui *g)
{
    WORD bw, ow, oh, left, top, tb, maxh;

    g->scr = LockPubScreen(NULL);
    if (!g->scr) return FALSE;
    g->vi = GetVisualInfo(g->scr, TAG_END);
    if (!g->vi) return FALSE;

    /* The screen font, unless it would make the window too big: then Topaz 8. */
    tb   = g->scr->WBorTop + g->scr->Font->ta_YSize + 1;
    maxh = g->scr->Height - g->scr->BarHeight - 1;
    if (!openFont(g, g->scr->Font) && !openFont(g, &topaz8)) return FALSE;
    measure(g, &bw);
    ow = g->iw + g->scr->WBorLeft + g->scr->WBorRight;
    oh = g->ih + tb + g->scr->WBorBottom;
    if (g->iw > MAXW || ow > g->scr->Width || oh > maxh) {
        if (!openFont(g, &topaz8)) return FALSE;
        measure(g, &bw);
    }
    if (g->iw > MAXW) g->iw = MAXW;     /* Topaz 8 needs ~364: never hit */
    ow = g->iw + g->scr->WBorLeft + g->scr->WBorRight;
    oh = g->ih + tb + g->scr->WBorBottom;

    if (!createGadgets(g, bw)) return FALSE;

    /* near the top-left, but kept on the screen */
    left = 40; top = g->scr->BarHeight + 12;
    if (left + ow > g->scr->Width)  left = g->scr->Width - ow;
    if (top + oh > g->scr->Height)  top  = g->scr->Height - oh;
    if (left < 0) left = 0;
    if (top < 0)  top = 0;

    g->win = OpenWindowTags(NULL,
        (ULONG)WA_Title,        (ULONG)NBR_NAME,
        (ULONG)WA_Left,         left, (ULONG)WA_Top, top,
        (ULONG)WA_InnerWidth,   g->iw, (ULONG)WA_InnerHeight, g->ih,
        (ULONG)WA_Flags,        WFLG_DRAGBAR | WFLG_DEPTHGADGET |
                                WFLG_CLOSEGADGET | WFLG_ACTIVATE,
        (ULONG)WA_IDCMP,        IDCMP_CLOSEWINDOW | IDCMP_REFRESHWINDOW |
                                IDCMP_MENUPICK | IDCMP_VANILLAKEY | BUTTONIDCMP,
        (ULONG)WA_Gadgets,      (ULONG)g->glist,
        (ULONG)WA_PubScreen,    (ULONG)g->scr,
        (ULONG)WA_NewLookMenus, TRUE,           /* V39; ignored on 2.04 */
        TAG_END);
    if (!g->win) return FALSE;

    if ((g->menu = CreateMenus(menu_def, TAG_END)) != NULL) {
        if (LayoutMenus(g->menu, g->vi, (ULONG)GTMN_NewLookMenus, TRUE, TAG_END))
            SetMenuStrip(g->win, g->menu);
        else {
            FreeMenus(g->menu);
            g->menu = NULL;
        }
    }

    GT_RefreshWindow(g->win, NULL);
    showStatus(g, bsdctl(BSDCTL_QUERY, NULL, NULL, 0));
    return TRUE;
}

static void closeGui(struct Gui *g)
{
    if (g->win) {
        if (g->menu) ClearMenuStrip(g->win);
        CloseWindow(g->win);
    }
    if (g->menu)  FreeMenus(g->menu);
    if (g->glist) FreeGadgets(g->glist);
    if (g->font)  CloseFont(g->font);
    if (g->vi)    FreeVisualInfo(g->vi);
    if (g->scr)   UnlockPubScreen(NULL, g->scr);
}

/* A plain key: the underlined letter of a button. */
static int keyToGadget(UWORD code)
{
    switch (code | 0x20) {          /* lower case */
    case 'd': return GID_DISCONNECT;
    case 'c': return GID_CONNECT;
    case 'r': return GID_REFRESH;
    case 'p': return GID_PING;
    case 'n': return GID_STATUS;
    }
    return 0;
}

static void eventLoop(struct Gui *g)
{
    struct IntuiMessage *imsg;

    while (!g->quit) {
        WaitPort(g->win->UserPort);
        while ((imsg = GT_GetIMsg(g->win->UserPort))) {
            ULONG          cls  = imsg->Class;
            UWORD          code = imsg->Code;
            struct Gadget *gad  = (struct Gadget *)imsg->IAddress;
            GT_ReplyIMsg(imsg);

            if (g->quit) continue;          /* just drain the port */
            switch (cls) {
            case IDCMP_CLOSEWINDOW:
                g->quit = TRUE;
                break;
            case IDCMP_GADGETUP:
                doAction(g, gad->GadgetID);
                break;
            case IDCMP_VANILLAKEY:
                if (code == 0x1B) g->quit = TRUE;           /* Esc */
                else doAction(g, keyToGadget(code));
                break;
            case IDCMP_MENUPICK:
                while (code != MENUNULL && !g->quit) {
                    struct MenuItem *it = ItemAddress(g->menu, code);
                    if (!it) break;
                    doMenu(g, (ULONG)GTMENUITEM_USERDATA(it));
                    code = it->NextSelect;
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

    (void)vers;
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
