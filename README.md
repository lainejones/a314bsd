# a314BSD — bsdsocket.library over A314

Replaces `bsdsocket.library` on the Amiga with a proxy that forwards all
AmiTCP-compatible BSD socket calls to a Python service on the Raspberry Pi.
The Pi's TCP/IP stack does the actual networking; the Amiga 68000 does nothing.

**Tested working:** AWeb / IBrowse (HTTP), smb2fs (SMB shares), ping, test_bsd HTTP.

> **HTTPS?** This base library is deliberately SSL-free. For HTTPS/TLS, add the
> companion **[a314SSLlib](../a314SSLlib)** project — it layers AmiSSL-compatible
> TLS on top of this base (TLS offloaded to the Pi), with no changes to a314bsd.

---

## Requirements

- A314 expansion board and `a314d` running on the Pi  
- AmigaOS 3.x with the A314 device driver installed  
- Python 3.7+ on the Pi (uses the A314 venv automatically)  
- m68k-amigaos-gcc in WSL for rebuilding the Amiga library (optional)

---

## Installation

### Pi (one time)

```bash
# From the a314bsd/pi/ directory on the Pi:
chmod +x install.sh
sudo ./install.sh
```

The script:
1. Copies `bsdsocket.py` and `bsdctl.py` to `/opt/a314/`
2. Adds `bsdsocket` and `bsdctl` to `a314d.conf`
3. Grants the `a314d` service user write access to the flag directory
   (so NetBridge's network on/off can create its pause flag)
4. Restarts `a314d`

After this, the services launch automatically whenever the Amiga opens
`bsdsocket.library` or the `bsdctl` service. No manual startup is needed
after reboots.

### Amiga (one time)

Copy the compiled files to the Amiga:

```
bsdsocket.library  ->  LIBS:
NetBridge          ->  anywhere (has an icon) — network control panel
bsdnet             ->  C: (or anywhere on your path) — CLI equivalent
```

Only `bsdsocket.library` is required; `NetBridge` and `bsdnet` are optional
tools for pausing/resuming the proxy and pinging. No `Startup-Sequence`
changes are needed.

---

## Usage

Any software that calls `OpenLibrary("bsdsocket.library", 4)` will work:

- **Web browsers**: AWeb, IBrowse — open normally, browse as usual
- **SMB shares**: `smb2fs mount smb://user:pass@server/share mountpoint:`
- **FTP clients**: any AmiTCP-compatible FTP client
- **Custom tools**: `test_bsd example.com 80 /` (included smoke test)

### Network control (NetBridge)

Pause/resume the proxy without unloading anything (backed by the `bsdctl`
service, `pi/bsdctl.py`). While paused, **new** connections are refused with
`ENETDOWN`; connections already open keep working.

- **CLI**: `bsdnet stop` (offline) / `bsdnet start` (online) / `bsdnet status`
- **GUI**: `NetBridge` — a small GadTools control panel with a live status
  line, **Disconnect / Connect / Refresh**, a **Host** field, and **Ping** /
  **Net Status** (results shown in a requester). Talks the `bsdctl` service
  directly, so it works even when `bsdsocket.library` is paused.

---

## Build (Amiga library)

Only needed if you modify `bsdsocket.c` or `lib_start.S`:

```bash
# In WSL:
cd /mnt/c/projects/a314bsd/amiga
PATH=/opt/amiga/bin:/usr/bin:/bin make
# Output: bsdsocket.library
```

---

## Architecture

```
Amiga app
  |  OpenLibrary("bsdsocket.library")
  v
bsdsocket.library (LIBS:)
  |  A314_CONNECT "bsdsocket"
  |  A314_WRITE  [opcode|seq|arglen|args]   ← request
  |  A314_READ   [seq|result|datalen|data]  ← response
  v
A314 shared memory ring buffer (252 bytes/direction max)
  v
a314d (Pi) → forks bsdsocket.py on first connect
  v
bsdsocket.py
  |  Python socket() / connect() / send() / recv() / ...
  v
Pi TCP/IP stack → network
```

One `bsdsocket.py` process handles all Amiga tasks. Each `OpenLibrary` call
creates a new A314 stream (one per Amiga task); `CloseLibrary` tears it down.

---

## Protocol

Defined in `include/bsd_proto.h`.

| Direction | Layout |
|-----------|--------|
| Request (Amiga → Pi) | `opcode(1)` `seq(1)` `arglen(2)` `inlen(2)` `args[arglen]`, then `inlen` bytes in raw ≤252-byte chunks |
| Response (Pi → Amiga) | `seq(1)` `result(4)` `errno(4)` `outlen(2)`, then `outlen` bytes in raw ≤252-byte chunks |

`result >= 0`: success / return value  
`result < 0`: failure, `errno` holds the BSD/AmiTCP errno value

**Hard limit**: the A314 ring buffer is 256 bytes per direction; each packet
payload must be ≤ 252 bytes, so data is streamed as raw chunks after the
header. `inlen`/`outlen` are 16-bit: `send()`/`SSL_write` move at most 32 KB
per call (`send` returns the short count, `SSL_write` loops internally),
`sendto()` at most 65535 bytes, and the Pi returns at most 32 KB per `recv`.

### Wire protocol v6 (library 4.55, 2026-09-25)

Adds two opcodes so `WaitSelect()` honours its signal mask (e.g. Ctrl-C)
even with no timeout:

- `BSDOP_PROTOVER` (25): the Pi answers with its protocol version (6).
  The library probes once per session, the first time `WaitSelect()` is
  called with a non-empty signal mask.
- `BSDOP_CANCEL` (26): a bare request header, **never answered**. While a
  `WAITSELECT` is blocked on the Pi, the caller `Wait()`s on the reply *and*
  its signal mask; on a signal the dispatcher sends `CANCEL`, the Pi wakes
  its `select()` through a per-session self-pipe and answers the
  `WAITSELECT` normally, and `WaitSelect()` returns with the received
  signals in `*sigmask`. A `CANCEL` that arrives after the select finished
  is silently dropped, so there is always exactly one response.

Backward compatible both ways: a v5 Pi service answers `PROTOVER` with
`-1`/`EINVAL`, and the library then never sends `CANCEL` (signals are only
checked after the select returns, as before); a v5 library never sends
either opcode. Update both sides to get the interruptible `WaitSelect()`.

The same release also byte-swaps integer socket options (`SO_RCVBUF`,
`SO_LINGER`, `TCP_NODELAY`, ...) and the `FIONREAD` count on the
little-endian Pi, which were previously returned in the wrong byte order.

### Wire protocol v7 (library 4.56, 2026-09-30)

`ReleaseSocket()`, `ReleaseCopyOfSocket()` and `ObtainSocket()` work (they
were stubs returning -1). A daemon that accepts a connection and hands it to
another process, like a BBS listener passing a caller to its node, needs them.
Every opener's sockets live in the one Pi service, so the Pi keeps a table of
released sockets by id (`UNIQUE_ID` = -1 picks one); one that is never
obtained is closed after 5 minutes. Two new opcodes, `BSDOP_RELEASESOCKET`
(27) and `BSDOP_OBTAINSOCKET` (28). A v6 Pi answers them like unknown opcodes,
so the calls fail exactly as the old stubs did. Verified on the A1200 with
NilBBS, whose listener hands every call to a node this way.

**Hardware-verified 2026-09-30** on the A1200 (68030, a314 clockport, OS 3.2.3)
with the a314SSLlib `4.55+ssl` build and its Pi service: `amiga/bsdlive`
against `test/liveserver.py` on the Pi passed 100000-byte sends and receives
(4 × `send()`, largest 32768), and a `WaitSelect()` with a 60 s timeout
returned 0 with `SIGBREAKF_CTRL_C` 5.4 s after a `Break`, with the next
request on the same library still in step. wget (HTTP), NetHarness, AmiTime
and Amelinium over HTTPS all work. A v5 Pi answered the version probe with
"unimplemented opcode 25" and the library fell back as designed.

Running it: copy `test/liveserver.py` to the Pi and start it
(`python3 liveserver.py`; `-dump` logs raw bytes instead), then on the Amiga
`bsdlive BIG` and `bsdlive WAIT` (Break the process while it waits). The Pi
service is spawned once and outlives Amiga reboots: after updating
`bsdsocket.py`, kill it (`kill -9`; it ignores SIGTERM) while the Amiga
reboots, so the next connect starts the new code.

---

## Known limitations / stubs

| Function | Status |
|----------|--------|
| `ObtainSocket` / `ReleaseSocket` | Returns `EOPNOTSUPP` |
| `sendmsg` / `recvmsg` | Returns `EOPNOTSUPP` |
| `getservbyname` / `getservbyport` | ✅ Implemented |
| `SocketBaseTagList` ERRNOPTR tag | Ignored (use `Errno()`) |
| HTTPS / TLS | Not in base — add the companion **[a314SSLlib](../a314SSLlib)** project (Pi-side TLS offload; Amiga clock need not be correct — the Pi verifies certs) |

---

## Files

```
amiga/
  lib_start.S      ROM tag, LVO jump table (50 entries)
  bsdsocket.c      C implementation of all socket calls
  netbridge.c      NetBridge — GadTools network control panel
  bsdnet.c         CLI control tool (bsdnet start|stop|status)
  test_bsd.c       Smoke-test HTTP client
  Makefile

include/
  bsd_proto.h      Wire protocol opcodes and packet structs
  inline/bsdsocket.h   Amiga inline stubs
  netinclude/      AmiTCP-compatible socket headers

pi/
  bsdsocket.py     Pi asyncio service
  bsdctl.py        Network-control backend (pause/resume, ping, status)
  install.sh       One-shot installer for the Pi
```
