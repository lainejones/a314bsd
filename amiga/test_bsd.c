/*
 * test_bsd.c - a314BSD smoke test
 *
 * Opens bsdsocket.library, resolves a hostname, makes a TCP connection,
 * sends a minimal HTTP/1.0 GET, reads and prints the first 512 bytes.
 *
 * Build:
 *   make test_bsd
 *
 * Run on Amiga:
 *   test_bsd [host] [port] [path]
 *   test_bsd example.com 80 /
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

static void println(STRPTR msg)
{
    print(msg);
    print("\n");
}

/* Minimal decimal-to-string; writes into buf, returns pointer to start */
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

int main(int argc, char **argv)
{
    struct hostent    *he;
    struct sockaddr_in sa;
    struct RDArgs     *rdargs;
    LONG               rda[3];
    LONG               fd = -1, n, total = 0;
    BYTE               buf[512];
    BYTE               hostbuf[128];
    BYTE               pathbuf[128];
    STRPTR             host = "example.com";
    LONG               port = 80;
    STRPTR             path = "/";
    BYTE               numbuf[16];
    BYTE               req[256];
    UWORD              reqlen;
    UWORD              i;

    (void)argc; (void)argv;

    /* DOSBase is already open by crt0; SysBase is at address 4 */

    /* Parse optional HOST/PORT/PATH from CLI using ReadArgs.
     * Copy strings to local buffers BEFORE FreeArgs, because rda[] pointers
     * into ReadArgs' internal buffer become dangling after FreeArgs(). */
    rda[0] = rda[1] = rda[2] = 0;
    rdargs = ReadArgs((STRPTR)"HOST,PORT/N,PATH", rda, NULL);
    if (rdargs) {
        if (rda[0]) {
            STRPTR s = (STRPTR)rda[0];
            for (i = 0; i < (UWORD)(sizeof(hostbuf) - 1) && s[i]; i++)
                hostbuf[i] = s[i];
            hostbuf[i] = 0;
            host = hostbuf;
        }
        if (rda[1]) port = *(LONG *)rda[1];
        if (rda[2]) {
            STRPTR s = (STRPTR)rda[2];
            for (i = 0; i < (UWORD)(sizeof(pathbuf) - 1) && s[i]; i++)
                pathbuf[i] = s[i];
            pathbuf[i] = 0;
            path = pathbuf;
        }
        FreeArgs(rdargs);
    }

    println("a314BSD test");
    print("Opening bsdsocket.library... ");

    SocketBase = OpenLibrary("bsdsocket.library", 4);
    if (!SocketBase) { println("FAILED"); return 20; }
    println("OK");

    /* DNS lookup */
    print("Resolving ");
    print(host);
    print("... ");
    he = gethostbyname(host);
    if (!he) {
        print("FAILED errno=");
        println(itoa(Errno(), numbuf, sizeof(numbuf)));
        goto cleanup;
    }
    println(Inet_NtoA(*(ULONG *)he->h_addr));

    /* Build socket */
    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        print("socket() FAILED errno=");
        println(itoa(Errno(), numbuf, sizeof(numbuf)));
        goto cleanup;
    }

    /* Connect */
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((UWORD)port);
    sa.sin_addr.s_addr = *(ULONG *)he->h_addr;

    print("Connecting to port ");
    print(itoa(port, numbuf, sizeof(numbuf)));
    print("... ");

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        print("FAILED errno=");
        println(itoa(Errno(), numbuf, sizeof(numbuf)));
        goto cleanup;
    }
    println("OK");

    /* Build and send HTTP request */
    reqlen = 0;
    {
        STRPTR parts[] = { "GET ", path, " HTTP/1.0\r\nHost: ", host,
                           "\r\nConnection: close\r\n\r\n", NULL };
        UWORD i = 0;
        while (parts[i]) {
            STRPTR p = parts[i++];
            while (*p && reqlen < (UWORD)(sizeof(req) - 1))
                req[reqlen++] = *p++;
        }
    }

    print("Sending request (");
    print(itoa(reqlen, numbuf, sizeof(numbuf)));
    print(" bytes)... ");
    n = send(fd, req, reqlen, 0);
    if (n < 0) {
        print("FAILED errno=");
        println(itoa(Errno(), numbuf, sizeof(numbuf)));
        goto cleanup;
    }
    println("OK");

    /* Read response */
    println("Response:");
    println("---");
    while (total < 512) {
        LONG want = sizeof(buf) - 1 < 512 - total ? sizeof(buf) - 1 : 512 - total;
        n = recv(fd, buf, want, 0);
        if (n < 0) {
            print("recv error errno=");
            println(itoa(Errno(), numbuf, sizeof(numbuf)));
            break;
        }
        if (n == 0) {
            println("recv EOF");
            break;
        }
        buf[n] = 0;
        print((STRPTR)buf);
        total += n;
    }
    println("---");
    print("Received ");
    print(itoa(total, numbuf, sizeof(numbuf)));
    println(" bytes.");

cleanup:
    if (fd >= 0)     CloseSocket(fd);
    if (SocketBase)  CloseLibrary(SocketBase);
    return 0;
}
