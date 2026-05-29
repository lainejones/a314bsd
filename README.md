# a314BSD — bsdsocket.library over A314

Replaces `bsdsocket.library` on the Amiga with a proxy that forwards all
AmiTCP-compatible BSD socket calls to a Python service on the Raspberry Pi.
The Pi's TCP/IP stack does the actual networking; the Amiga 68000 does nothing.

**Tested working:** IBrowse & AWeb (HTTP **and HTTPS**), smb2fs (SMB shares),
ping (ICMP), DNS, test_bsd HTTP. HTTPS/TLS is offloaded to the Pi — see the
[HTTPS / TLS](#https--tls-ssl-offload-to-the-pi) section.

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

Only needed if you modify the sources:

```bash
# In WSL:
cd /mnt/c/projects/a314bsd/amiga
PATH=/opt/amiga/bin:/usr/bin:/bin make
# Output: bsdsocket.library, amissl.library, amisslmaster.library
```

(The `TAG_DONE redefined` warning from `amissl.c` is benign.)

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

## HTTPS / TLS (SSL offload to the Pi)

HTTPS works by offloading **all** TLS to the Pi — the Amiga 68000 does no crypto.
Two companion libraries present the standard AmiSSL / OpenSSL LVO API to Amiga
browsers and proxy every SSL operation over A314 to OpenSSL on the Pi:

- **`amissl.library`** — implements the AmiSSL 4/5 (OpenSSL) function table.
  `SSL_CTX_*`, `SSL_*`, `BIO_*`, cipher and X509 calls are forwarded to the Pi
  through 11 new bsdsocket SSL LVOs (`bsd_ssl_*`, LVO -828..-888); the opaque
  `SSL_CTX*` / `SSL*` handles are integer IDs allocated by the Pi.
- **`amisslmaster.library`** — the AmiSSL master library apps open first
  (`OpenAmiSSLTagList`) to obtain the amissl base.

The Pi (`bsdsocket.py`) runs the real TLS via Python's `ssl` module (OpenSSL):
it builds the `SSL_CTX` with the system CA bundle, performs the handshake with
SNI, and **verifies the certificate chain and hostname itself**. Because the Pi
does the verification, the **Amiga's clock does not need to be correct** — cert
date-validation happens on the Pi. Plaintext flows Amiga↔Pi over A314; ciphertext
only ever exists between the Pi and the server.

Notable engineering (all Pi-side and version-independent):
- TLS-aware `FIONREAD` / `WaitSelect` (uses `SSL_pending`) so select/FIONREAD-
  driven clients read the whole record instead of truncating the response.
- Correct non-blocking `SSL_get_error` — `WANT_READ` is reported as "retry",
  not as a fatal error (a fatal report made AWeb dump raw, unparsed responses).
- `SSL_CTX` kept for the process lifetime (some clients free a ctx then reuse
  the same handle for the next connection).
- Per-client quirks handled on the Pi: AWeb's `Accept-Encoding` is rewritten to
  `identity` (it advertises gzip but cannot decode it); the iBrowse-specific
  `+0x206` AmiSSL-base patch is gated to iBrowse's own task so it can never
  touch another application's memory.

**Tested:** iBrowse 3.x ✅ and AWeb 3.6b8 ✅ — pages, images, and downloads over
HTTPS. Amelinium 0.7.4 connects and receives complete data correctly but crashes
in its own rendering ("painting") stage — an upstream bug in that early beta,
not in this stack.

### Install (HTTPS)

Copy **all three** libraries to `LIBS:` and deploy the Pi service as usual:

```
amissl.library  amisslmaster.library  bsdsocket.library   ->  LIBS:
bsdsocket.py    ->  /opt/a314/   (or run pi/install.sh)
```

Then point a TLS-capable, AmiSSL-using browser (iBrowse, AWeb) at an `https://`
URL.

**No real AmiSSL installation is required, and no `AmiSSL:` assign.** These two
libraries are a self-contained, drop-in re-implementation of the AmiSSL API; the
Pi supplies the CA bundle and performs all certificate verification. Verified by
cold-boot test: iBrowse and AWeb both browse and download over HTTPS with only
the three libraries in `LIBS:` present — no AmiSSL install, no `AmiSSL:` assign.

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
| HTTPS / TLS | ✅ Implemented via Pi-side TLS offload (see [HTTPS / TLS](#https--tls-ssl-offload-to-the-pi)). The Amiga clock does **not** need to be correct — the Pi verifies certificates. |

---

## Files

```
amiga/
  lib_start.S          ROM tag, LVO jump table (148 entries incl. 11 SSL)
  bsdsocket.c          C implementation of all socket calls (canonical base)
  bsdsocket_main.c     Unity build: #includes bsdsocket.c + bsd_ssl_stubs.c;
                       adds the iBrowse-only AmiSSL-base patch (built as bsdsocket.o)
  bsd_ssl_stubs.c      SSL LVO implementations + getaddrinfo (forward to the Pi)
  amissl.c             amissl.library — AmiSSL/OpenSSL LVO API shim
  amissl_start.S         (ROM tag + 5452-entry AmiSSL function table)
  amisslmaster.c       amisslmaster.library — AmiSSL master shim
  amisslmaster_start.S
  bsdnet.c             CLI control tool (bsdnet start|stop|status)
  test_bsd.c           Smoke-test HTTP client
  Makefile

include/
  bsd_proto.h          Wire protocol opcodes and packet structs (incl. SSL docs)
  ssl_proto.h          SSL opcode #defines (BSDOP_SSL_* = 50–60) + SSL_ERROR consts
  ssl_lvo.h            Amiga-side BSDSSL_LVO_* offsets + extended negsize
  inline/bsdsocket.h   Amiga inline stubs
  netinclude/          AmiTCP-compatible socket headers

pi/
  bsdsocket.py         Pi asyncio service (sockets + SSL/TLS handlers)
  install.sh           One-shot installer for the Pi
```

---

## Credits & attribution

All code in this project is original. **No third-party source is copied or
bundled.** The SSL shim implements the AmiSSL / OpenSSL *interface* (function
table / LVO layout) so that existing browsers bind to it — but the
implementation is our own. With thanks to:

- **A314** — Niklas Ekström's A314 board and `a314.device` / `a314d` transport
  that this whole library runs on. <https://github.com/niklasekstrom/a314>
  (Architectural patterns were observed; his bsdsocket source was **not** copied.)
- **AmiSSL** — Oliver Roberts. `amissl.library` / `amisslmaster.library` target
  the AmiSSL 4/5 (OpenSSL) LVO API and FD layout for binary compatibility with
  AmiSSL-using browsers. <https://github.com/jens-maus/amissl>
- **OpenSSL** — performs the actual TLS on the Pi, used via Python's standard
  `ssl` module. <https://www.openssl.org/>
- **Python** standard library (`asyncio`, `socket`, `ssl`) — the Pi service.

Consulted for reference only during development (read to understand behaviour;
**not** copied or redistributed):

- **AWeb3** source (amigazen) — to understand AWeb's local certificate-check
  flow. <https://github.com/amigazen/AWeb3>
- **iBrowse** runtime behaviour — observed via disassembly to derive the
  iBrowse-specific AmiSSL-base workaround.

The browsers used for testing (iBrowse, AWeb, Amelinium) are third-party
software and are **not** included in or distributed with this project.
