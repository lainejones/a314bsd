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
1. Copies `bsdsocket.py` to `/opt/a314/`
2. Adds `bsdsocket` to `a314d.conf`
3. Restarts `a314d`

After this, the service launches automatically whenever the Amiga opens
`bsdsocket.library`. No manual startup is needed after reboots.

### Amiga (one time)

Copy the compiled library to the Amiga:

```
bsdsocket.library  ->  LIBS:
```

That is all. No `Startup-Sequence` changes are needed.

---

## Usage

Any software that calls `OpenLibrary("bsdsocket.library", 4)` will work:

- **Web browsers**: AWeb, IBrowse — open normally, browse as usual
- **SMB shares**: `smb2fs mount smb://user:pass@server/share mountpoint:`
- **FTP clients**: any AmiTCP-compatible FTP client
- **Custom tools**: `test_bsd example.com 80 /` (included smoke test)
- **bsdnet**: `bsdnet status` / `bsdnet stop` / `bsdnet start`

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
| Request (Amiga → Pi) | `opcode(1)` `seq(1)` `arglen(2)` `args[arglen]` |
| Response (Pi → Amiga) | `seq(1)` `result(4)` `datalen(2)` `data[datalen]` |

`result >= 0`: success / return value  
`result < 0`: `-errno` (BSD/AmiTCP errno values)

**Hard limit**: the A314 ring buffer is 256 bytes per direction; each message
payload must be ≤ 252 bytes. `recv` is capped at 245 bytes per call; `send`
at 242 bytes. The caller loops for larger transfers.

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
  bsdnet.c         CLI control tool (bsdnet start|stop|status)
  test_bsd.c       Smoke-test HTTP client
  Makefile

include/
  bsd_proto.h      Wire protocol opcodes and packet structs
  inline/bsdsocket.h   Amiga inline stubs
  netinclude/      AmiTCP-compatible socket headers

pi/
  bsdsocket.py     Pi asyncio service
  install.sh       One-shot installer for the Pi
```
