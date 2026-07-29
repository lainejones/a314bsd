/*
 * fdchurn.c - fd allocation churn test for the a314bsd fd_set overflow fix
 *
 * Regression test for the Pi-side alloc_fd change (lowest-free reuse):
 * the old monotonic allocator handed out fd > 31 after ~29 sockets in one
 * session, at which point WaitSelect's 32-bit fd_set mask could no longer
 * represent the fd and select-driven reads silently hung/timed out.
 *
 * Phase 1: 40 sequential connect / WaitSelect / recv / close cycles against
 *          an HTTP server, all in ONE library session.  With the fix every
 *          cycle reuses fd 3 and every WaitSelect fires; with the old
 *          allocator cycles beyond ~29 get fd > 31 and time out.
 * Phase 2: hold 6 sockets open at once, close the middle two, open two more
 *          (must fill the holes, staying < 8), then close all.
 *
 * Run on Amiga:  fdchurn [HOST] [PORT/N] [PATH]
 *   defaults: 192.168.50.33 8099 /bench/bench.bin
 *   (any URL path works; the test only reads the first bytes of the
 *   response and closes.)
 */

#include <exec/types.h>
#include <exec/libraries.h>
#include <dos/dos.h>
#include <dos/rdargs.h>
#include <proto/exec.h>
#include <proto/dos.h>

#include <netinclude/sys/socket.h>
#include <netinclude/netinet/in.h>
#include <netinclude/netdb.h>
#include <netinclude/sys/select.h>
#include <inline/bsdsocket.h>

struct Library *SocketBase;

static void print(STRPTR msg)
{
    LONG len = 0;
    while (msg[len]) len++;
    Write(Output(), msg, len);
}

static void println(STRPTR msg) { print(msg); print("\n"); }

static STRPTR itoa(LONG v, BYTE *buf, UWORD bufsize)
{
    UWORD i = bufsize - 1;
    BYTE neg = 0;
    buf[i] = 0;
    if (v < 0) { neg = 1; v = -v; }
    do { buf[--i] = '0' + (v % 10); v /= 10; } while (v && i);
    if (neg && i) buf[--i] = '-';
    return (STRPTR)&buf[i];
}

static void print_num(STRPTR label, LONG v)
{
    BYTE nb[16];
    print(label);
    print(itoa(v, nb, sizeof nb));
}

/* Connect a fresh socket to ip:port.  Returns fd or -1. */
static LONG conn(ULONG ip, LONG port)
{
    struct sockaddr_in sa;
    LONG fd = socket(AF_INET, SOCK_STREAM, 0);
    UWORD i;
    UBYTE *p;
    if (fd < 0) return -1;
    p = (UBYTE *)&sa;
    for (i = 0; i < sizeof sa; i++) p[i] = 0;
    sa.sin_family = AF_INET;
    sa.sin_port = (UWORD)port;
    sa.sin_addr.s_addr = ip;
    if (connect(fd, (APTR)&sa, sizeof sa) < 0) {
        CloseSocket(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char **argv)
{
    struct RDArgs *rdargs;
    LONG   rda[3];
    STRPTR host = (STRPTR)"192.168.50.33";
    LONG   port = 8099;
    STRPTR path = (STRPTR)"/bench/bench.bin";
    BYTE   hostbuf[128], pathbuf[128];
    BYTE   req[256], buf[512];
    ULONG  ip;
    LONG   fd, n, round, maxfd = -1, fails = 0, timeouts = 0;
    UWORD  i, reqlen;

    (void)argc; (void)argv;

    rda[0] = rda[1] = rda[2] = 0;
    rdargs = ReadArgs((STRPTR)"HOST,PORT/N,PATH", rda, NULL);
    if (rdargs) {
        if (rda[0]) {
            STRPTR s = (STRPTR)rda[0];
            for (i = 0; i < sizeof(hostbuf) - 1 && s[i]; i++) hostbuf[i] = s[i];
            hostbuf[i] = 0;
            host = hostbuf;
        }
        if (rda[1]) port = *(LONG *)rda[1];
        if (rda[2]) {
            STRPTR s = (STRPTR)rda[2];
            for (i = 0; i < sizeof(pathbuf) - 1 && s[i]; i++) pathbuf[i] = s[i];
            pathbuf[i] = 0;
            path = pathbuf;
        }
        FreeArgs(rdargs);
    }

    println("fdchurn: a314bsd fd_set overflow regression test");

    SocketBase = OpenLibrary((STRPTR)"bsdsocket.library", 4);
    if (!SocketBase) { println("FAIL: no bsdsocket.library"); return 20; }

    {
        struct hostent *he = gethostbyname(host);
        if (!he) { println("FAIL: DNS"); CloseLibrary(SocketBase); return 20; }
        ip = *(ULONG *)he->h_addr_list[0];
    }

    /* Build the GET request once. */
    reqlen = 0;
    {
        STRPTR parts[5];
        parts[0] = (STRPTR)"GET ";  parts[1] = path;
        parts[2] = (STRPTR)" HTTP/1.0\r\nHost: ";
        parts[3] = host;  parts[4] = (STRPTR)"\r\n\r\n";
        for (i = 0; i < 5; i++) {
            STRPTR s = parts[i];
            UWORD j = 0;
            while (s[j] && reqlen < sizeof(req) - 1) req[reqlen++] = s[j++];
        }
    }

    /* ---- Phase 1: 40 sequential cycles ---- */
    println("phase 1: 40x connect/select/recv/close (one session)");
    for (round = 0; round < 40; round++) {
        fd = conn(ip, port);
        if (fd < 0) { fails++; continue; }
        if (fd > maxfd) maxfd = fd;

        if (send(fd, (APTR)req, reqlen, 0) < 0) {
            fails++;
            CloseSocket(fd);
            continue;
        }

        /* The critical check: does WaitSelect see this fd as readable?
         * Old allocator: fd > 31 after ~29 rounds -> mask overflow ->
         * 5s timeout here.  New allocator: fd stays tiny, fires fast. */
        {
            fd_set rfds;
            struct timeval tv;
            LONG r;
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);
            tv.tv_sec = 5; tv.tv_usec = 0;
            r = WaitSelect(fd + 1, &rfds, NULL, NULL, &tv, NULL);
            if (r <= 0 || !FD_ISSET(fd, &rfds)) {
                timeouts++;
                print_num("  TIMEOUT at round ", round);
                print_num(" fd=", fd);
                print("\n");
                CloseSocket(fd);
                continue;
            }
        }

        n = recv(fd, (APTR)buf, sizeof buf, 0);
        if (n <= 0) fails++;
        CloseSocket(fd);
    }
    print_num("phase 1 done: maxfd=", maxfd);
    print_num(" fails=", fails);
    print_num(" select_timeouts=", timeouts);
    print("\n");

    /* ---- Phase 2: concurrent sockets + hole filling ---- */
    println("phase 2: 6 concurrent, close 2, open 2 (hole reuse)");
    {
        LONG fds[8];
        LONG p2max = -1, p2fail = 0;
        for (i = 0; i < 6; i++) {
            fds[i] = conn(ip, port);
            if (fds[i] < 0) p2fail++;
            else if (fds[i] > p2max) p2max = fds[i];
        }
        /* free two in the middle, then allocate two more — the new
         * allocator must fill the holes rather than grow past them */
        if (fds[2] >= 0) CloseSocket(fds[2]);
        if (fds[3] >= 0) CloseSocket(fds[3]);
        fds[6] = conn(ip, port);
        fds[7] = conn(ip, port);
        if (fds[6] < 0 || fds[7] < 0) p2fail++;
        if (fds[6] > p2max) p2max = fds[6];
        if (fds[7] > p2max) p2max = fds[7];
        for (i = 0; i < 8; i++) {
            if (i == 2 || i == 3) continue;
            if (fds[i] >= 0) CloseSocket(fds[i]);
        }
        print_num("phase 2 done: maxfd=", p2max);
        print_num(" fails=", p2fail);
        print("\n");
        if (p2max >= 0 && p2max < 10 && p2fail == 0 &&
            maxfd >= 0 && maxfd < 10 && fails == 0 && timeouts == 0)
            println("RESULT: PASS");
        else
            println("RESULT: FAIL (see counts above)");
    }

    CloseLibrary(SocketBase);
    return 0;
}
