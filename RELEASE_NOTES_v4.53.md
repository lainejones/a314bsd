# a314bsd v4.53 — NetBridge network control

a314bsd replaces **bsdsocket.library** on the Amiga with a proxy that forwards
all AmiTCP-compatible BSD socket calls over the A314 link to a Python service on
the Raspberry Pi. The Pi's TCP/IP stack does the real networking; the Amiga
68000 does none. Tested working with AWeb / IBrowse (HTTP), SMB shares
(smb2-handler), ping, and FTP.

This release adds **NetBridge** — a small "Roadie for a314bsd" control panel —
and extends the control service behind it.

## What's new

**NetBridge (GadTools control panel)**
- Live status line: ONLINE (accepting connections) / OFFLINE (paused).
- **Disconnect** / **Connect** — pause or resume the proxy. While paused, *new*
  connections are refused with ENETDOWN; connections already open keep working.
- **Refresh** — re-read the current state.
- **Host** field + **Ping** — ping any host or IP through the Pi (returns average
  round-trip time / reachability in a requester).
- **Net Status** — reports the proxy state plus the Pi's hostname and IP.
- Talks the "bsdctl" A314 service directly via a314.device, so it works even
  when bsdsocket.library itself is paused.

**bsdnet (CLI)** — the same control from the shell:

    bsdnet stop      (offline)
    bsdnet start     (online)
    bsdnet status

**Pi side**
- New "bsdctl" service (pi/bsdctl.py) backs both NetBridge and bsdnet.
- The bsdctl wire protocol is widened from a 1-byte command / 1-byte status to a
  command(+argument) request and a status + length + text reply, adding STATUS
  and PING.
- bsdsocket.py honours the shared pause flag in its CONNECT handler.

## Fixes found on real hardware

- **Monotonic A314 socket ID** — a314.device rejects a socket ID it just closed,
  so a fixed ID worked once but every following connect (each Refresh) failed.
  NetBridge and the bsdnet CLI now use a fresh incrementing ID per connect.
- **GadTools border offset** — the status line no longer renders on the title
  bar, and the empty gap at the bottom of the window is gone.
- **ASCII text** — replaced a multi-byte em-dash that rendered as garbage in the
  topaz font; widened the status gadget so the line is no longer clipped.
- **install.sh** — grants the a314d service user write access to /opt/a314 so
  bsdctl can actually create the pause flag (a314d commonly runs as a non-root
  user while the directory is root-owned, which silently broke network on/off).

## Install

**Amiga** (copy once):

    bsdsocket.library   ->  LIBS:
    NetBridge           ->  anywhere (has an icon)
    bsdnet              ->  C: (or anywhere on your path)

**Pi** (once), from the pi/ drawer:

    sudo ./install.sh

The service starts on demand whenever the Amiga opens bsdsocket.library — no
Startup-Sequence changes, no manual startup after reboots.

## HTTPS / TLS

This base library is deliberately SSL-free. For https:// support, add the
companion **a314SSLlib** project — it layers AmiSSL-compatible TLS on top
(offloaded to the Pi), with no changes to a314bsd.

## Archive contents

    bsdsocket.library      the library (-> LIBS:)
    NetBridge  +  .info    control panel + icon
    bsdnet                 CLI control tool
    README.md
    pi/bsdsocket.py        Pi service (base, SSL-free)
    pi/bsdctl.py           network-control backend
    pi/install.sh          one-shot Pi installer

## Credits

- Built on the A314 project by Niklas Ekström (a314d transport + service model).
  The a314bsd implementation is standalone.
- The Pi does all TCP/IP and ICMP via Python's socket and the system ping.
