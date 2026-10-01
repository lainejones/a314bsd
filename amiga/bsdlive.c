/*
 * bsdlive.c - on-hardware checks for the v4.55 changes
 *
 * Talks to test/liveserver.py (run it on the Pi: the proxy makes the
 * Amiga's connections from there, so 127.0.0.1 is the Pi itself).
 *
 *   bsdlive BIG  [host] [port]   one 100000-byte send() per call: a send
 *                                must come back short (<= 32768) and the
 *                                server must see every byte in order; then
 *                                100000 bytes back, checked
 *   bsdlive SMALL [host] [port]  a few small sends (for liveserver.py -dump)
 *   bsdlive WAIT [host] [port]   WaitSelect() on a quiet socket with
 *                                Ctrl-C in the mask; Break the process and
 *                                it must return at once with Ctrl-C set,
 *                                then a new request must still work
 *
 * Never call a function inside the arguments of an inline library macro
 * (send(s, l, strlen(l), 0)): the macro binds each argument to its register
 * as it goes, and the call clobbers the ones already bound (fd in d0).
 *
 * Build: make bsdlive
 */

#include <exec/types.h>
#include <dos/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <netinclude/sys/socket.h>
#include <netinclude/netinet/in.h>
#include <netinclude/netdb.h>
#include <netinclude/sys/select.h>
#include <inline/bsdsocket.h>

struct Library *SocketBase;

#define BIGN 100000L

static UBYTE buf[BIGN];

static UBYTE pat(LONG i) { return (UBYTE)((i * 7 + (i >> 8)) ^ 0x5A); }

static void out(const char *s) { printf("%s\n", s); fflush(stdout); }

static LONG tconnect(const char *host, int port)
{
    struct sockaddr_in sa;
    struct hostent *he;
    LONG s;

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = port;
    sa.sin_addr.s_addr = inet_addr((STRPTR)host);
    if (sa.sin_addr.s_addr == (ULONG)-1) {
        if (!(he = gethostbyname((STRPTR)host))) { out("FAIL resolve"); return -1; }
        memcpy(&sa.sin_addr, he->h_addr, 4);
    }
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { printf("FAIL socket errno %ld\n", Errno()); return -1; }
    if (connect(s, (struct sockaddr *)&sa, sizeof sa) < 0) {
        printf("FAIL connect errno %ld\n", Errno());
        CloseSocket(s);
        return -1;
    }
    return s;
}

static int sendline(LONG s, const char *l)
{
    LONG n = strlen(l), r = send(s, (UBYTE *)l, n, 0);
    if (r != n) printf("FAIL send(line, %ld) = %ld errno %ld\n", n, r, Errno());
    return r == n;
}

/* read one line (the server's answer) */
static int getline_s(LONG s, char *line, int max)
{
    int n = 0;
    char c;
    while (n < max - 1 && recv(s, (UBYTE *)&c, 1, 0) == 1) {
        if (c == '\n') break;
        line[n++] = c;
    }
    line[n] = 0;
    return n;
}

static int do_sink(const char *host, int port, LONG total, int verbose)
{
    char line[80];
    LONG s, i, done = 0, calls = 0, maxret = 0;
    int ok;

    if ((s = tconnect(host, port)) < 0) return 0;
    for (i = 0; i < total; i++) buf[i] = pat(i);
    sprintf(line, "S %ld\n", total);
    sendline(s, line);
    while (done < total) {
        LONG r = send(s, buf + done, total - done, 0);
        calls++;
        if (verbose) printf("  send(%ld) = %ld\n", total - done, r);
        if (r <= 0) { printf("FAIL send = %ld errno %ld\n", r, Errno()); CloseSocket(s); return 0; }
        if (r > maxret) maxret = r;
        done += r;
    }
    getline_s(s, line, sizeof line);
    CloseSocket(s);
    ok = (strncmp(line, "OK", 2) == 0) && maxret <= 32768;
    printf("%s sink %ld bytes in %ld send()s, largest %ld; server: %s\n",
           ok ? "PASS" : "FAIL", total, calls, maxret, line);
    return ok;
}

static int do_source(const char *host, int port, LONG total)
{
    char line[40];
    LONG s, got = 0, bad = -1, calls = 0;

    if ((s = tconnect(host, port)) < 0) return 0;
    sprintf(line, "R %ld\n", total);
    sendline(s, line);
    while (got < total) {
        LONG r = recv(s, buf + got, total - got, 0);
        calls++;
        if (r <= 0) break;
        got += r;
    }
    CloseSocket(s);
    for (LONG i = 0; i < got && bad < 0; i++)
        if (buf[i] != pat(i)) bad = i;
    printf("%s source %ld/%ld bytes in %ld recv()s%s\n",
           (got == total && bad < 0) ? "PASS" : "FAIL", got, total, calls,
           bad >= 0 ? " (pattern mismatch)" : "");
    return got == total && bad < 0;
}

static int do_wait(const char *host, int port)
{
    struct timeval tv;
    struct DateStamp a, b;
    fd_set rf;
    ULONG mask = SIGBREAKF_CTRL_C;
    LONG s, r, ticks;

    if ((s = tconnect(host, port)) < 0) return 0;
    sendline(s, "H\n");                     /* server stays quiet */
    FD_ZERO(&rf);
    FD_SET(s, &rf);
    tv.tv_sec = 60;
    tv.tv_usec = 0;
    out("waiting (Break me)");
    DateStamp(&a);
    r = WaitSelect(s + 1, &rf, NULL, NULL, &tv, &mask);
    DateStamp(&b);
    ticks = (b.ds_Minute - a.ds_Minute) * 3000 + (b.ds_Tick - a.ds_Tick);
    CloseSocket(s);
    printf("%s WaitSelect = %ld, mask %s, after %ld.%02ld s\n",
           (r == 0 && (mask & SIGBREAKF_CTRL_C) && ticks < 55 * 50) ? "PASS" : "FAIL",
           r, (mask & SIGBREAKF_CTRL_C) ? "CTRL_C" : "none", ticks / 50, (ticks % 50) * 2);
    /* the session must still be in step: a normal request right after */
    return do_sink(host, port, 5000, 0) && r == 0;
}

int main(int argc, char **argv)
{
    /* ReadArgs, not argv: libnix left argv[1] NULL under NetHarness EXEC */
    LONG opt[3] = { 0, 0, 0 };
    struct RDArgs *rda = ReadArgs("MODE,HOST,PORT/N", opt, NULL);
    const char *mode = opt[0] ? (const char *)opt[0] : "BIG";
    const char *host = opt[1] ? (const char *)opt[1] : "127.0.0.1";
    int port = opt[2] ? (int)*(LONG *)opt[2] : 5099;
    int ok;

    setvbuf(stdout, NULL, _IONBF, 0);   /* progress must survive a hang */
    if (!rda) { out("usage: bsdlive [BIG|WAIT|SMALL] [host] [port]"); return 20; }

    if (!(SocketBase = OpenLibrary("bsdsocket.library", 4))) { out("FAIL no bsdsocket.library"); return 20; }
    printf("bsdsocket.library %d.%d, mode %s\n", SocketBase->lib_Version,
           SocketBase->lib_Revision, mode);
    if (!strcasecmp(mode, "SMALL")) {           /* for liveserver.py -dump */
        LONG s = tconnect(host, port), r;
        if (s < 0) return 10;
        r = send(s, (UBYTE *)"PING1\n", 6, 0); printf("send 6 = %ld\n", r);
        r = send(s, (UBYTE *)"PING2\n", 6, 0); printf("send 6 = %ld\n", r);
        memset(buf, 'x', 300);
        r = send(s, buf, 300, 0); printf("send 300 = %ld\n", r);
        r = send(s, (UBYTE *)"END\n", 4, 0); printf("send 4 = %ld\n", r);
        Delay(50);
        CloseSocket(s);
        ok = 1;
    } else if (!strcasecmp(mode, "WAITNOSIG") || !strcasecmp(mode, "HOLD")) {
        /* idle-cost probes (run CPUMeter alongside): one quiet connected
           socket for 30 s, in a WaitSelect without a signal mask (the
           pre-v6 path), or with nothing pending at all */
        LONG s = tconnect(host, port);
        if (s < 0) return 10;
        sendline(s, "H\n");
        if (!strcasecmp(mode, "HOLD")) {
            out("holding 30 s");
            Delay(30 * 50);
        } else {
            struct timeval tv;
            fd_set rf;
            LONG r;
            FD_ZERO(&rf);
            FD_SET(s, &rf);
            tv.tv_sec = 30;
            tv.tv_usec = 0;
            out("WaitSelect 30 s, no signal mask");
            r = WaitSelect(s + 1, &rf, NULL, NULL, &tv, NULL);
            printf("WaitSelect = %ld\n", r);
        }
        CloseSocket(s);
        ok = 1;
    } else if (!strcasecmp(mode, "WAIT"))
        ok = do_wait(host, port);
    else
        ok = do_sink(host, port, BIGN, 1) & do_source(host, port, BIGN);
    CloseLibrary(SocketBase);
    FreeArgs(rda);
    out(ok ? "ALL PASS" : "SOME FAILED");
    return ok ? 0 : 10;
}
