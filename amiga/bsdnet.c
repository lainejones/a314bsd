/*
 * bsdnet.c - a314BSD control tool
 *
 * Talks to the "bsdctl" A314 service to start, stop, or query
 * the bsdsocket proxy.  Uses a314.device directly — does NOT
 * require bsdsocket.library to be functional.
 *
 * Usage:
 *   bsdnet start   - allow new connections (resume)
 *   bsdnet stop    - block new connections (pause)
 *   bsdnet status  - print current state
 *
 * Build:
 *   make bsdnet
 */

#include <exec/types.h>
#include <exec/io.h>
#include <exec/ports.h>
#include <exec/tasks.h>
#include <dos/dos.h>
#include <dos/rdargs.h>
#include <proto/exec.h>
#include <proto/dos.h>

#include "a314.h"

/* bsdctl command codes sent by the Amiga */
#define BSDCTL_QUERY   0x01
#define BSDCTL_PAUSE   0x02
#define BSDCTL_RESUME  0x03

/* bsdctl response codes from the Pi */
#define BSDCTL_RUNNING 0x01
#define BSDCTL_PAUSED  0x02
#define BSDCTL_OK      0x03

static void println(STRPTR s)
{
    LONG len = 0;
    while (s[len]) len++;
    Write(Output(), s, len);
    Write(Output(), "\n", 1);
}

int main(int argc, char **argv)
{
    struct MsgPort         *port = NULL;
    struct A314_IORequest  *ior  = NULL;
    struct RDArgs          *rdargs;
    LONG                    rda[1];
    UBYTE                   cmd  = BSDCTL_QUERY;
    UBYTE                   rsp  = 0;
    STRPTR                  arg;
    LONG                    rc   = 0;

    (void)argc; (void)argv;

    rda[0] = 0;
    rdargs = ReadArgs((STRPTR)"COMMAND/A", rda, NULL);
    if (!rdargs) {
        println("Usage: bsdnet start|stop|status");
        return 10;
    }
    arg = (STRPTR)rda[0];

    if (arg[0] == 's' || arg[0] == 'S') {
        if ((arg[1] == 't' || arg[1] == 'T') &&
            (arg[2] == 'o' || arg[2] == 'O'))
            cmd = BSDCTL_PAUSE;                     /* stop  */
        else if ((arg[1] == 't' || arg[1] == 'T') &&
                 (arg[3] == 'r' || arg[3] == 'R'))
            cmd = BSDCTL_RESUME;                    /* start */
        else
            cmd = BSDCTL_QUERY;                     /* status */
    } else if (arg[0] == 'p' || arg[0] == 'P') {
        cmd = BSDCTL_PAUSE;
    } else if (arg[0] == 'r' || arg[0] == 'R') {
        cmd = BSDCTL_RESUME;
    } else {
        FreeArgs(rdargs);
        println("Usage: bsdnet start|stop|status");
        return 10;
    }
    FreeArgs(rdargs);

    port = CreateMsgPort();
    if (!port) { println("bsdnet: CreateMsgPort failed"); return 20; }

    ior = (struct A314_IORequest *)CreateIORequest(port,
                                    sizeof(struct A314_IORequest));
    if (!ior) {
        println("bsdnet: CreateIORequest failed");
        rc = 20; goto cleanup_port;
    }

    if (OpenDevice(A314_NAME, 0, (struct IORequest *)ior, 0) != 0) {
        println("bsdnet: cannot open a314.device");
        rc = 20; goto cleanup_ior;
    }

    /* Connect to bsdctl service */
    ior->a314_Socket  = (ULONG)FindTask(NULL);
    ior->a314_Buffer  = (STRPTR)"bsdctl";
    ior->a314_Length  = 6;
    ior->a314_Request.io_Command = A314_CONNECT;

    if (DoIO((struct IORequest *)ior) != A314_CONNECT_OK) {
        println("bsdnet: cannot connect (is bsdsocket.py running on the Pi?)");
        rc = 20; goto cleanup_dev;
    }

    /* Send command byte */
    ior->a314_Request.io_Command = A314_WRITE;
    ior->a314_Buffer = (STRPTR)&cmd;
    ior->a314_Length = 1;
    if (DoIO((struct IORequest *)ior) != A314_WRITE_OK) {
        println("bsdnet: write failed");
        rc = 20; goto cleanup_dev;
    }

    /* Read response byte */
    ior->a314_Request.io_Command = A314_READ;
    ior->a314_Buffer = (STRPTR)&rsp;
    ior->a314_Length = 1;
    if (DoIO((struct IORequest *)ior) != A314_READ_OK) {
        println("bsdnet: read failed");
        rc = 20; goto cleanup_dev;
    }

    /* Signal end-of-stream */
    ior->a314_Request.io_Command = A314_EOS;
    DoIO((struct IORequest *)ior);

    switch (rsp) {
    case BSDCTL_RUNNING: println("bsdsocket: running"); break;
    case BSDCTL_PAUSED:  println("bsdsocket: stopped"); break;
    case BSDCTL_OK:      println("bsdsocket: ok");      break;
    default:             println("bsdsocket: unknown response"); rc = 10; break;
    }

cleanup_dev:
    CloseDevice((struct IORequest *)ior);
cleanup_ior:
    DeleteIORequest((struct IORequest *)ior);
cleanup_port:
    DeleteMsgPort(port);
    return (LONG)rc;
}
