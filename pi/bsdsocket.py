#!/usr/bin/env python3
"""
bsdsocket.py - a314bsd Pi service  (v4.52 / arch v5)

Architecture v5 differs from v4: each Amiga library call results in ONE
Linux syscall on the Pi side (no per-chunk request loop).  Data streams back
to the Amiga as a sequence of raw chunks following a single response header.
This puts the chunk-by-chunk handshake inside our wire protocol so the Amiga
library doesn't need to round-trip with the Pi for every 245 bytes.

Wire framing (see include/bsd_proto.h):
  REQ packet (Amiga -> Pi):
    hdr (6B BE): opcode(1) seq(1) arglen(2) inlen(2)
    args[arglen]
    -- if inlen > 0, ceil(inlen / 252) raw chunks follow
  RES packet (Pi -> Amiga):
    hdr (11B BE): seq(1) result(4 signed) errno(4) outlen(2)
    -- if outlen > 0, ceil(outlen / 252) raw chunks follow

Transport: a314d MSG_DATA chunks, each <= 252 bytes payload.  A single
PKT_DATA contains exactly one wire frame piece (a header or a raw chunk);
the receiver counts bytes against the header's len fields.

To make recv block correctly:
  - BSDOP_RECV calls socket.recv(maxlen) once, blocks until at least 1 byte
    or EOF or error
  - whatever Linux returns is sent back in one shot via N data chunks
  - Amiga library reads RES then drains N chunks, all from one dispatcher
    task -- wget's calling task does a single Wait on a reply signal
"""

import asyncio
import errno as _errno
import logging
import socket
import ssl as _ssl
import struct
import sys
from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    format='%(levelname)s %(asctime)s %(name)s:%(lineno)d: %(message)s')
log = logging.getLogger('bsdsocket')
log.setLevel(logging.WARNING)

# ---------------------------------------------------------------------------
# a314d link
# ---------------------------------------------------------------------------

A314D_HOST   = 'localhost'
A314D_PORT   = 7110
SERVICE_NAME = b'bsdsocket'

# a314d message types (Pi <-> a314d)
MSG_REGISTER_REQ     = 1
MSG_REGISTER_RES     = 2
MSG_CONNECT          = 9
MSG_CONNECT_RESPONSE = 10
MSG_DATA             = 11
MSG_EOS              = 12
MSG_RESET            = 13

# Max payload per a314d MSG_DATA chunk.  This is enforced by the underlying
# A314 ring buffer (PktHdr.length is a UBYTE and the ring is 256B per
# direction; a314d uses up to 252 bytes of payload per chunk).
MAX_CHUNK = 252

# Cap on bytes returned from a single BSDOP_RECV / BSDOP_RECVFROM RPC.
# Streaming a 65536-byte recv back to the Amiga requires ~261 A314 chunks
# in a single burst, which appears to overwhelm the Amiga-side dispatcher
# / ring buffer pacing during heavy SMB transfers (manifests as smb2-handler
# "Poll Failed").  Stream sockets are allowed to return short reads, so we
# silently clamp maxlen — the Amiga app just calls recv again for the rest.
MAX_RECV_PER_RPC = 32768

# ---------------------------------------------------------------------------
# BSD opcodes (must match include/bsd_proto.h)
# ---------------------------------------------------------------------------

BSDOP_SOCKET        = 1
BSDOP_CLOSE         = 2
BSDOP_CONNECT       = 3
BSDOP_BIND          = 4
BSDOP_LISTEN        = 5
BSDOP_ACCEPT        = 6
BSDOP_SEND          = 7
BSDOP_RECV          = 8
BSDOP_SENDTO        = 9
BSDOP_RECVFROM      = 10
BSDOP_SETSOCKOPT    = 11
BSDOP_GETSOCKOPT    = 12
BSDOP_SHUTDOWN      = 13
BSDOP_GETSOCKNAME   = 14
BSDOP_GETPEERNAME   = 15
BSDOP_GETHOSTBYNAME = 16
BSDOP_GETHOSTBYADDR = 17
BSDOP_INET_ADDR     = 18
BSDOP_INET_NTOA     = 19
BSDOP_GETSERVBYNAME = 20
BSDOP_GETSERVBYPORT = 21
BSDOP_WAITSELECT    = 22
BSDOP_GETHOSTNAME   = 23
BSDOP_IOCTL         = 24

# SSL opcodes — must match ssl_proto.h and a314SSLlib/include/ssl_proto.h
BSDOP_SSL_CTX_NEW    = 50
BSDOP_SSL_CTX_FREE   = 51
BSDOP_SSL_NEW        = 52
BSDOP_SSL_FREE       = 53
BSDOP_SSL_SET_FD     = 54
BSDOP_SSL_SET_SNI    = 55
BSDOP_SSL_CONNECT    = 56
BSDOP_SSL_SHUTDOWN   = 57
BSDOP_SSL_READ       = 58
BSDOP_SSL_WRITE      = 59
BSDOP_SSL_GET_ERROR  = 60

# SSL_get_error return codes — match OpenSSL values
SSL_ERROR_NONE        = 0
SSL_ERROR_SSL         = 1
SSL_ERROR_WANT_READ   = 2
SSL_ERROR_WANT_WRITE  = 3
SSL_ERROR_SYSCALL     = 5
SSL_ERROR_ZERO_RETURN = 6

# ---------------------------------------------------------------------------
# AmiTCP <-> Linux constant translation
# ---------------------------------------------------------------------------

_AMIGA_SOL_SOCKET = 0xffff
_LINUX_SOL_SOCKET = socket.SOL_SOCKET

_AMIGA_TO_LINUX_SO = {
    0x0001: socket.SO_DEBUG, 0x0002: socket.SO_ACCEPTCONN,
    0x0004: socket.SO_REUSEADDR, 0x0008: socket.SO_KEEPALIVE,
    0x0010: socket.SO_DONTROUTE, 0x0020: socket.SO_BROADCAST,
    0x0080: socket.SO_LINGER, 0x0100: socket.SO_OOBINLINE,
    0x1001: socket.SO_SNDBUF, 0x1002: socket.SO_RCVBUF,
    0x1007: socket.SO_ERROR, 0x1008: socket.SO_TYPE,
}

def translate_sockopt(level, optname):
    if level == _AMIGA_SOL_SOCKET:
        return _LINUX_SOL_SOCKET, _AMIGA_TO_LINUX_SO.get(optname, optname)
    return level, optname

# AmiTCP MSG_* -> Linux MSG_* translation.
# Low bits (OOB=1, PEEK=2, DONTROUTE=4, EOR=8, TRUNC=16, CTRUNC=32) match.
# The two that differ between AmiTCP and Linux:
#   MSG_WAITALL:  AmiTCP 0x0040  vs  Linux 0x0100
#   MSG_DONTWAIT: AmiTCP 0x0080  vs  Linux 0x0040
# CRITICAL: Without this translation, PEEK is silently dropped — the Pi
# consumes data from the TCP socket that wget thinks it merely peeked at,
# causing wget's HTTP parser to see garbage on its followup non-PEEK recv.
_AMIGA_MSG_LOWBITS  = 0x003F
_AMIGA_MSG_WAITALL  = 0x0040
_AMIGA_MSG_DONTWAIT = 0x0080

def translate_msgflags(amiga_flags):
    linux_flags = amiga_flags & _AMIGA_MSG_LOWBITS
    if amiga_flags & _AMIGA_MSG_WAITALL:
        linux_flags |= socket.MSG_WAITALL
    if amiga_flags & _AMIGA_MSG_DONTWAIT:
        linux_flags |= socket.MSG_DONTWAIT
    return linux_flags

# Linux errno -> BSD/AmiTCP errno (only the values that differ)
_LINUX_TO_BSD_ERRNO = {
    11:  35,   # EAGAIN/EWOULDBLOCK
    98:  48,   # EADDRINUSE
    99:  49,   # EADDRNOTAVAIL
    101: 51,   # ENETUNREACH
    103: 53,   # ECONNABORTED
    104: 54,   # ECONNRESET
    105: 55,   # ENOBUFS
    106: 56,   # EISCONN
    107: 57,   # ENOTCONN
    108: 58,   # ESHUTDOWN
    110: 60,   # ETIMEDOUT
    111: 61,   # ECONNREFUSED
    113: 65,   # EHOSTUNREACH
}

def to_bsd_errno(linux_err):
    return _LINUX_TO_BSD_ERRNO.get(linux_err, linux_err)

# ---------------------------------------------------------------------------
# Per-stream (= per-Amiga-task) session state
# ---------------------------------------------------------------------------

class Session:
    """One Amiga OpenLibrary = one Session = one a314d stream.  Owns a
    table of Linux sockets keyed by the small fd we hand back to the Amiga."""

    def __init__(self, service, stream_id):
        self.service = service
        self.stream_id = stream_id
        self.sockets = {}             # fd -> socket.socket
        self.next_fd = 3              # 0/1/2 reserved
        self.rx_buffer = bytearray()  # bytes received from a314d, not yet parsed
        # SOCK_RAW or SOCK_DGRAM+ICMP fds — recvfrom uses 1-sec timeout
        # (returns EINTR on timeout so ping can send next echo)
        self.raw_fds = set()
        # SOCK_DGRAM+ICMP fds that need synthesised IPv4 header on recvfrom
        # (Linux strips the IP header from SOCK_DGRAM_ICMP receives; the
        # Amiga ping app expects to see the IP header it would get from RAW)
        self.dgram_icmp_fds = set()

        # SSL state — opaque integer IDs allocated here, independent of fd numbers.
        # ssl_ctx_map: ctx_id (int) -> ssl.SSLContext
        # ssl_map:     ssl_id (int) -> dict(ctx_id, fd, sni, sock)
        #   sock is None until SSL_connect succeeds, then it is the ssl.SSLSocket.
        #   After connect, sess.sockets[fd] is also replaced with the ssl.SSLSocket
        #   so that the fd is transparently upgraded in the session table.
        self.ssl_ctx_map     = {}
        self.ssl_map         = {}
        self.next_ssl_ctx_id = 1
        self.next_ssl_id     = 1

    # ---- socket table ----

    def alloc_fd(self, sock):
        fd = self.next_fd
        self.next_fd += 1
        self.sockets[fd] = sock
        return fd

    def free_fd(self, fd):
        sock = self.sockets.pop(fd, None)
        self.raw_fds.discard(fd)
        self.dgram_icmp_fds.discard(fd)
        if sock is not None:
            try: sock.close()
            except: pass

    def close_all(self):
        for fd, sock in list(self.sockets.items()):
            try: sock.close()
            except: pass
        self.sockets.clear()
        self.raw_fds.clear()
        self.dgram_icmp_fds.clear()
        # Clean up SSL objects before clearing state
        for entry in self.ssl_map.values():
            if entry.get('sock') is not None:
                try: entry['sock'].unwrap()
                except: pass
        self.ssl_map.clear()
        self.ssl_ctx_map.clear()

# ---------------------------------------------------------------------------
# Wire protocol helpers
# ---------------------------------------------------------------------------

REQ_HDR_SIZE = 6
RES_HDR_SIZE = 11

# REQ hdr: opcode(B) seq(B) arglen(H) inlen(H) big-endian
_REQ_HDR = struct.Struct('>BBHH')
# RES hdr: seq(B) result(i) errno(i) outlen(H) big-endian
_RES_HDR = struct.Struct('>BiiH')

def encode_res_hdr(seq, result, errno_val, outlen):
    return _RES_HDR.pack(seq & 0xff, result, errno_val, outlen & 0xffff)

# ---------------------------------------------------------------------------
# Operation dispatch
# ---------------------------------------------------------------------------

_OPNAME = {1:'SOCKET', 2:'CLOSE', 3:'CONNECT', 4:'BIND', 5:'LISTEN',
           6:'ACCEPT', 7:'SEND', 8:'RECV', 9:'SENDTO', 10:'RECVFROM',
           11:'SETSOCKOPT', 12:'GETSOCKOPT', 13:'SHUTDOWN', 14:'GETSOCKNAME',
           15:'GETPEERNAME', 16:'GETHOSTBYNAME', 17:'GETHOSTBYADDR',
           18:'INET_ADDR', 19:'INET_NTOA', 20:'GETSERVBYNAME', 21:'GETSERVBYPORT',
           22:'WAITSELECT', 23:'GETHOSTNAME', 24:'IOCTL',
           50:'SSL_CTX_NEW', 51:'SSL_CTX_FREE', 52:'SSL_NEW', 53:'SSL_FREE',
           54:'SSL_SET_FD', 55:'SSL_SET_SNI', 56:'SSL_CONNECT', 57:'SSL_SHUTDOWN',
           58:'SSL_READ', 59:'SSL_WRITE', 60:'SSL_GET_ERROR'}

# ---------------------------------------------------------------------------
# SSL operation dispatcher
# ---------------------------------------------------------------------------

# Build 30: SSL contexts are PROCESS-GLOBAL, not per-session.  iBrowse creates one
# SSL_CTX on its first connection's session, then reuses that ctx_id across many
# SEPARATE connection sessions (parallel image loads) — often AFTER the creating
# session has already closed.  A per-session ctx map made SSL_new(ctx) return NULL on
# those sessions, so iBrowse aborted each connection ("interrupted by remote host").
# ssl.SSLContext is explicitly designed to be shared across many connections.
_GLOBAL_SSL_CTX     = {}      # ctx_id -> ssl.SSLContext (shared by ALL sessions)
_GLOBAL_NEXT_CTX_ID = [1]     # mutable holder for the next ctx_id counter

# Build 32: SSL_CTX*/SSL* handles must LOOK like valid pointers.  Some apps (AWeb 3.6)
# sanity-check the returned handle: they reject anything < 0x1000 or >= 0xFFFFFFF0 as a
# bogus pointer and abort.  Our handles are opaque integers, so hand them out in a
# plausible, aligned pointer range instead of 1,2,3...  The shim passes handles through
# unchanged and we key our maps by the same value, so nothing else changes.  Bases sit in
# low chip RAM so that even if an app dereferences the handle it reads real memory (no
# bus error) rather than crashing.  ctx and ssl use distinct bases.
_HANDLE_CTX_BASE = 0x00018000   # SSL_CTX handles: 0x18010, 0x18020, ...
_HANDLE_SSL_BASE = 0x00028000   # SSL handles:     0x28010, 0x28020, ...

def _ctx_handle(n):  return _HANDLE_CTX_BASE + (n & 0x7FFF) * 0x10
def _ssl_handle(n):  return _HANDLE_SSL_BASE + (n & 0x7FFF) * 0x10


def _ssl_dispatch(sess: Session, opcode: int, args: bytes, indata: bytes) -> Tuple[int, int, bytes]:
    """Handle one SSL opcode.  Called from dispatch_op when opcode >= 50.
    Returns (result, errno_val, outdata) using the same convention as dispatch_op.

    All blocking operations (SSL_connect, SSL_read) are safe to block here
    because dispatch_op already runs in a thread pool via run_in_executor."""

    if opcode == BSDOP_SSL_CTX_NEW:
        try:
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            # Pi uses the system CA bundle — the whole point of this shim.
            # check_hostname=True requires the app to supply an SNI hostname;
            # apps should call SSL_set_tlsext_host_name() before SSL_connect().
            ctx.check_hostname = True
            ctx.verify_mode    = _ssl.CERT_REQUIRED
            ctx.load_default_certs()
        except Exception as e:
            log.warning('SSL_CTX_new failed: %s', e)
            return (0, 12, b'')   # 0 = NULL = failure; ENOMEM
        ctx_id = _ctx_handle(_GLOBAL_NEXT_CTX_ID[0])
        _GLOBAL_NEXT_CTX_ID[0] += 1
        _GLOBAL_SSL_CTX[ctx_id] = ctx
        log.warning('SSL_CTX_new -> ctx_id=0x%x (global; %d ctx total)',
                    ctx_id, len(_GLOBAL_SSL_CTX))
        return (ctx_id, 0, b'')

    elif opcode == BSDOP_SSL_CTX_FREE:
        (ctx_id,) = struct.unpack_from('>I', args)
        # Do NOT actually free the context.  iBrowse calls SSL_CTX_free but then
        # REUSES the same ctx handle for later connections (e.g. a download after a
        # page load).  Because the ctx map is process-global and the handle is an
        # opaque id, popping the entry makes the next SSL_new fail with "unknown
        # ctx_id" -> iBrowse reports "connection interrupted by remote host".
        # Contexts are cheap and bounded (apps reuse a handful), so keep them for
        # the process lifetime.  Log only.  (This intentionally tolerates iBrowse's
        # free-then-reuse; a real per-handle free is not safe under that pattern.)
        log.debug('SSL_CTX_free ctx_id=0x%08x (kept; %d ctx live)',
                  ctx_id, len(_GLOBAL_SSL_CTX))
        return (0, 0, b'')

    elif opcode == BSDOP_SSL_NEW:
        (ctx_id,) = struct.unpack_from('>I', args)
        if ctx_id not in _GLOBAL_SSL_CTX:
            log.warning('SSL_new: unknown ctx_id=%d (global keys=%s)',
                        ctx_id, list(_GLOBAL_SSL_CTX.keys()))
            return (0, 9, b'')   # 0 = NULL = failure; EBADF
        ssl_id = _ssl_handle(sess.next_ssl_id)
        sess.next_ssl_id += 1
        sess.ssl_map[ssl_id] = {'ctx_id': ctx_id, 'fd': None, 'sni': None, 'sock': None,
                                'last_ssl_err': SSL_ERROR_NONE}
        log.debug('SSL_new ctx_id=0x%x -> ssl_id=0x%x', ctx_id, ssl_id)
        return (ssl_id, 0, b'')

    elif opcode == BSDOP_SSL_FREE:
        (ssl_id,) = struct.unpack_from('>I', args)
        entry = sess.ssl_map.pop(ssl_id, None)
        if entry and entry['sock'] is not None:
            try: entry['sock'].unwrap()
            except: pass
        log.debug('SSL_free ssl_id=%d', ssl_id)
        return (0, 0, b'')

    elif opcode == BSDOP_SSL_SET_FD:
        (ssl_id, fd) = struct.unpack_from('>IH', args)
        entry = sess.ssl_map.get(ssl_id)
        if entry is None:
            log.warning('SSL_set_fd: unknown ssl_id=%d', ssl_id)
            return (-1, 9, b'')
        if fd not in sess.sockets:
            # fd was created in a different session (e.g. iBrowse opens its own
            # bsdsocket session for TCP; amissl.library opens a separate session
            # for SSL ops).  Search all other sessions for the fd and move it
            # into this session so SSL_connect can use it.
            # Moving (not copying) prevents double-close: if the source session
            # later calls BSDOP_CLOSE for this fd, free_fd() finds nothing and
            # returns 0 safely; actual close happens when this session tears down.
            found_sock = None
            source_sess = None
            for other_sess in list(sess.service.sessions.values()):
                if other_sess is not sess and fd in other_sess.sockets:
                    found_sock = other_sess.sockets[fd]
                    source_sess = other_sess
                    break
            if found_sock is None:
                log.warning('SSL_set_fd: fd=%d not found in any session '
                            'for ssl_id=%d', fd, ssl_id)
                return (-1, 9, b'')
            # Adopt the socket: remove from source, add to this session.
            source_sess.sockets.pop(fd, None)
            sess.sockets[fd] = found_sock
            log.warning('SSL_set_fd: adopted fd=%d from session %d '
                        'into session %d (cross-session)',
                        fd, source_sess.stream_id, sess.stream_id)
        entry['fd'] = fd
        log.debug('SSL_set_fd ssl_id=%d fd=%d', ssl_id, fd)
        return (0, 0, b'')

    elif opcode == BSDOP_SSL_SET_SNI:
        # args: ssl_id(4) nlen(1) name[nlen]
        (ssl_id, nlen) = struct.unpack_from('>IB', args)
        entry = sess.ssl_map.get(ssl_id)
        if entry is None:
            log.warning('SSL_set_sni: unknown ssl_id=%d', ssl_id)
            return (-1, 9, b'')
        try:
            sni = args[5:5 + nlen].decode('ascii', errors='replace')
        except Exception:
            sni = ''
        entry['sni'] = sni
        log.debug('SSL_set_sni ssl_id=%d sni=%r', ssl_id, sni)
        return (0, 0, b'')

    elif opcode == BSDOP_SSL_CONNECT:
        (ssl_id,) = struct.unpack_from('>I', args)
        entry = sess.ssl_map.get(ssl_id)
        if entry is None:
            log.warning('SSL_connect: unknown ssl_id=%d', ssl_id)
            return (-1, 9, b'')
        if entry['fd'] is None:
            log.warning('SSL_connect: no fd set for ssl_id=%d', ssl_id)
            return (-1, 9, b'')
        raw_sock = sess.sockets.get(entry['fd'])
        if raw_sock is None:
            log.warning('SSL_connect: fd=%d not in session', entry['fd'])
            return (-1, 9, b'')
        ctx = _GLOBAL_SSL_CTX.get(entry['ctx_id'])
        if ctx is None:
            log.warning('SSL_connect: ctx_id=%d gone', entry['ctx_id'])
            return (-1, 9, b'')
        sni = entry['sni']
        log.debug('SSL_connect ssl_id=%d fd=%d sni=%r', ssl_id, entry['fd'], sni)
        try:
            if not sni:
                # No SNI hostname — disable cert verification (e.g. bare-IP HTTPS)
                ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = _ssl.CERT_NONE
                log.warning('SSL_connect ssl_id=%d: no SNI — cert verify disabled', ssl_id)
            # wrap_socket does the full TLS handshake synchronously.
            # Safe to block here: dispatch runs in a thread pool, not the asyncio loop.
            ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=sni or None)
            # Replace raw socket in the session table so fd is now the SSL socket.
            sess.sockets[entry['fd']] = ssl_sock
            entry['sock'] = ssl_sock
            log.debug('SSL_connect ssl_id=%d OK cipher=%s proto=%s',
                      ssl_id, ssl_sock.cipher(), ssl_sock.version())
            return (0, 0, b'')
        except _ssl.SSLCertVerificationError as e:
            log.warning('SSL_connect ssl_id=%d cert verify failed: %s', ssl_id, e)
            return (-1, 1, b'')   # EPERM
        except _ssl.SSLError as e:
            log.warning('SSL_connect ssl_id=%d TLS error: %s', ssl_id, e)
            return (-1, 5, b'')   # EIO
        except OSError as e:
            log.warning('SSL_connect ssl_id=%d OS error: %s', ssl_id, e)
            return (-1, to_bsd_errno(e.errno or 5), b'')

    elif opcode == BSDOP_SSL_SHUTDOWN:
        (ssl_id,) = struct.unpack_from('>I', args)
        entry = sess.ssl_map.get(ssl_id)
        if entry is None or entry['sock'] is None:
            return (0, 0, b'')   # nothing to shut down
        try:
            entry['sock'].shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        log.debug('SSL_shutdown ssl_id=%d', ssl_id)
        return (0, 0, b'')

    elif opcode == BSDOP_SSL_READ:
        # args: ssl_id(4) maxlen(4)
        (ssl_id, maxlen) = struct.unpack_from('>II', args)
        entry = sess.ssl_map.get(ssl_id)
        if entry is None or entry['sock'] is None:
            log.warning('SSL_read: ssl_id=%d not connected', ssl_id)
            return (-1, 9, b'')
        maxlen = min(maxlen, MAX_RECV_PER_RPC)
        try:
            data = entry['sock'].recv(maxlen)
        except _ssl.SSLWantReadError:
            # Non-blocking socket, data not ready yet.  This is NORMAL, not fatal.
            # Record WANT_READ so SSL_get_error reports it correctly -> the client
            # (AWeb) waits via WAITSELECT and retries instead of aborting the fetch.
            entry['last_ssl_err'] = SSL_ERROR_WANT_READ
            return (-1, to_bsd_errno(11), b'')   # 11=EAGAIN -> Amiga EWOULDBLOCK(35)
        except _ssl.SSLWantWriteError:
            entry['last_ssl_err'] = SSL_ERROR_WANT_WRITE
            return (-1, to_bsd_errno(11), b'')
        except _ssl.SSLZeroReturnError:
            entry['last_ssl_err'] = SSL_ERROR_ZERO_RETURN
            return (0, 0, b'')   # clean TLS shutdown = EOF
        except _ssl.SSLError as e:
            entry['last_ssl_err'] = SSL_ERROR_SSL
            log.warning('SSL_read ssl_id=%d error: %s', ssl_id, e)
            return (-1, 5, b'')
        except OSError as e:
            entry['last_ssl_err'] = SSL_ERROR_SYSCALL
            return (-1, to_bsd_errno(e.errno or 5), b'')
        if not data:
            entry['last_ssl_err'] = SSL_ERROR_ZERO_RETURN
            return (0, 0, b'')   # EOF
        entry['last_ssl_err'] = SSL_ERROR_NONE
        return (len(data), 0, data)

    elif opcode == BSDOP_SSL_WRITE:
        # args: ssl_id(4); indata = bytes to send
        (ssl_id,) = struct.unpack_from('>I', args)
        entry = sess.ssl_map.get(ssl_id)
        if entry is None or entry['sock'] is None:
            log.warning('SSL_write: ssl_id=%d not connected', ssl_id)
            return (-1, 9, b'')
        if not indata:
            return (0, 0, b'')
        # Neutralize Accept-Encoding so the origin returns UNCOMPRESSED content.
        # The Pi terminates TLS, so SSL_write receives the browser's plaintext HTTP
        # request and we can rewrite it before encrypting to the server.  AWeb 3.6
        # advertises "Accept-Encoding: gzip" but cannot decode gzip -> it renders the
        # raw compressed bytes and fails.  Rewriting the header value to "identity"
        # makes the server send plain HTML.  Version-independent (matches the header
        # line, no fixed offsets) and harmless to gzip-capable browsers (iBrowse/
        # Amelinium just receive uncompressed content, still valid).  Only a COMPLETE
        # header line (terminated by CRLF) is rewritten, so a request split across
        # writes is never corrupted.
        orig_len = len(indata)   # bytes the Amiga handed us; report consumption vs this
        # Only AWeb needs Accept-Encoding neutralised: it advertises "gzip" but cannot
        # actually decode it.  iBrowse and Amelinium decode gzip natively, so leave their
        # requests untouched — forcing identity bloats every response and the much larger
        # uncompressed page appears to trip a client-side crash in Amelinium (beta).
        # Detect AWeb by its self-identified User-Agent (version-independent), rewrite only then.
        import re
        if b'AWeb' in indata:
            try:
                indata = re.sub(rb'(?i)(\r\nAccept-Encoding:)[^\r\n]*(\r\n)',
                                rb'\1 identity\2', indata, count=1)
            except Exception:
                pass
        try:
            n = entry['sock'].send(indata)
            # If the whole (possibly-rewritten) request went out, the caller's entire
            # original buffer was consumed -> report orig_len so its write accounting
            # matches what it asked to send (the +4 from gzip->identity is internal).
            entry['last_ssl_err'] = SSL_ERROR_NONE
            if n >= len(indata):
                return (orig_len, 0, b'')
            return (min(n, orig_len), 0, b'')
        except _ssl.SSLWantReadError:
            entry['last_ssl_err'] = SSL_ERROR_WANT_READ
            return (-1, to_bsd_errno(11), b'')
        except _ssl.SSLWantWriteError:
            entry['last_ssl_err'] = SSL_ERROR_WANT_WRITE
            return (-1, to_bsd_errno(11), b'')
        except _ssl.SSLError as e:
            entry['last_ssl_err'] = SSL_ERROR_SSL
            log.warning('SSL_write ssl_id=%d error: %s', ssl_id, e)
            return (-1, 5, b'')
        except OSError as e:
            entry['last_ssl_err'] = SSL_ERROR_SYSCALL
            return (-1, to_bsd_errno(e.errno or 5), b'')

    elif opcode == BSDOP_SSL_GET_ERROR:
        # args: ssl_id(4) ret(4 signed)
        (ssl_id, ret) = struct.unpack_from('>Ii', args)
        entry = sess.ssl_map.get(ssl_id)
        if entry is None:
            return (SSL_ERROR_SSL, 0, b'')
        if ret > 0:
            return (SSL_ERROR_NONE, 0, b'')
        elif ret == 0:
            return (SSL_ERROR_ZERO_RETURN, 0, b'')
        else:
            # ret < 0: report the REAL reason recorded by the last SSL_read/write.
            # Critically, a non-blocking WANT_READ must NOT be reported as a fatal
            # SSL_ERROR_SYSCALL, or clients that loop on select()+SSL_read (AWeb)
            # treat a normal "data not ready yet" as a hard failure, abort the fetch
            # ("Cannot connect") and dump the unparsed response into the renderer.
            return (entry.get('last_ssl_err', SSL_ERROR_SYSCALL), 0, b'')

    else:
        log.warning('unknown SSL opcode %d', opcode)
        return (-1, 22, b'')   # EINVAL

def dispatch_op(sess: Session, opcode: int, args: bytes, indata: bytes) -> Tuple[int, int, bytes]:
    """Execute one Amiga library call.  Returns (result, errno_val, outdata).
    Blocking ops (connect/recv/accept/waitselect) BLOCK the caller's a314d
    handler thread — that's fine because each Session has its own queue."""
    sess._op_count = getattr(sess, '_op_count', 0) + 1
    log.warning('dispatch sess=%d op=%s(%d) arglen=%d inlen=%d',
                sess.stream_id, _OPNAME.get(opcode, '?'), opcode,
                len(args), len(indata))
    try:
        if opcode == BSDOP_SOCKET:
            (dom, typ, proto) = struct.unpack_from('>HHH', args)
            fam = socket.AF_INET
            type_map = {1: socket.SOCK_STREAM, 2: socket.SOCK_DGRAM, 3: socket.SOCK_RAW}
            ltype = type_map.get(typ, socket.SOCK_STREAM)
            dgram_icmp_fallback = False
            try:
                sk = socket.socket(fam, ltype, proto)
            except PermissionError as e:
                if typ == 3 and proto == 1:
                    try:
                        sk = socket.socket(fam, socket.SOCK_DGRAM, proto)
                        dgram_icmp_fallback = True
                    except OSError:
                        return (-1, 13, b'')
                else:
                    return (-1, 13, b'')
            fd = sess.alloc_fd(sk)
            # SOCK_RAW (or the DGRAM_ICMP fallback) gets a 1-second internal
            # timeout so recvfrom doesn't block forever — real AmiTCP raw
            # sockets get interrupted by Amiga signals.  We fake that with
            # EINTR-on-timeout (see recvfrom handler below).
            if typ == 3 or dgram_icmp_fallback:
                sk.settimeout(1.0)
                sess.raw_fds.add(fd)
                if dgram_icmp_fallback:
                    sess.dgram_icmp_fds.add(fd)
            return (fd, 0, b'')

        elif opcode == BSDOP_CLOSE:
            (fd,) = struct.unpack_from('>H', args)
            sess.free_fd(fd)
            return (0, 0, b'')

        elif opcode == BSDOP_CONNECT:
            (fd, alen) = struct.unpack_from('>HB', args)
            addr_bytes = args[3:3+alen]
            (_fam, port) = struct.unpack_from('>HH', addr_bytes)
            ip = socket.inet_ntoa(addr_bytes[4:8])
            sk = sess.sockets.get(fd)
            if not sk: return (-1, 9, b'')   # EBADF
            try:
                sk.connect((ip, port))
                return (0, 0, b'')
            except OSError as e:
                return (-1, to_bsd_errno(e.errno or 0), b'')

        elif opcode == BSDOP_SEND:
            (fd, flags) = struct.unpack_from('>HH', args)
            sk = sess.sockets.get(fd)
            if not sk: return (-1, 9, b'')
            try:
                n = sk.send(indata, translate_msgflags(flags))
                return (n, 0, b'')
            except OSError as e:
                return (-1, to_bsd_errno(e.errno or 0), b'')

        elif opcode == BSDOP_RECV:
            (fd, flags, maxlen) = struct.unpack_from('>HHI', args)
            sk = sess.sockets.get(fd)
            if not sk: return (-1, 9, b'')
            effective_max = min(maxlen, MAX_RECV_PER_RPC)
            try:
                data = sk.recv(effective_max, translate_msgflags(flags))
                return (len(data), 0, data)
            except OSError as e:
                return (-1, to_bsd_errno(e.errno or 0), b'')

        elif opcode == BSDOP_SENDTO:
            # args: fd(2) flags(2) addrlen(1) addr[addrlen]
            (fd, flags, alen) = struct.unpack_from('>HHB', args)
            addr_bytes = args[5:5+alen]
            (_fam, port) = struct.unpack_from('>HH', addr_bytes)
            ip = socket.inet_ntoa(addr_bytes[4:8])
            sk = sess.sockets.get(fd)
            if not sk: return (-1, 9, b'')
            try:
                n = sk.sendto(indata, translate_msgflags(flags), (ip, port))
                return (n, 0, b'')
            except OSError as e:
                return (-1, to_bsd_errno(e.errno or 0), b'')

        elif opcode == BSDOP_RECVFROM:
            # args: fd(2) flags(2) maxlen(4)
            (fd, flags, maxlen) = struct.unpack_from('>HHI', args)
            sk = sess.sockets.get(fd)
            if not sk: return (-1, 9, b'')
            try:
                data, peer = sk.recvfrom(maxlen, translate_msgflags(flags))
                peer_ip, peer_port = peer[0], peer[1]
                # SOCK_DGRAM+ICMP returns ONLY the ICMP bytes (no IP header).
                # The Amiga ping app expects the SOCK_RAW layout with a leading
                # IP header.  Prepend a synthesised 20-byte IPv4 header so the
                # app sees what it expects.
                if fd in sess.dgram_icmp_fds:
                    try:
                        src_ip_bytes = socket.inet_aton(peer_ip)
                    except OSError:
                        src_ip_bytes = b'\x00\x00\x00\x00'
                    iphdr = struct.pack('>BBHHHBBH4s4s',
                        0x45, 0,                   # Ver=4 IHL=5, DSCP/ECN=0
                        20 + len(data),            # Total length
                        0, 0,                      # ID, Flags+FragOff
                        64, 1, 0,                  # TTL=64, Proto=ICMP, csum=0
                        src_ip_bytes,              # Source address
                        b'\x00\x00\x00\x00',       # Dest (ignored by ping)
                    )
                    data = iphdr + data
                sockaddr = (struct.pack('>HH', socket.AF_INET, peer_port)
                            + socket.inet_aton(peer_ip)
                            + b'\x00' * 8)
                out = struct.pack('>B', 16) + sockaddr + data
                return (len(data), 0, out)
            except socket.timeout:
                # Raw socket internal 1-second timeout — return EINTR so the
                # caller (e.g. ping) can send the next echo request.
                return (-1, 4, b'')   # EINTR
            except OSError as e:
                return (-1, to_bsd_errno(e.errno or 0), b'')

        elif opcode == BSDOP_GETSOCKOPT:
            # args: fd(2) level(2) optname(2) maxlen(2)
            (fd, level, optname, maxlen) = struct.unpack_from('>HHHH', args)
            sk = sess.sockets.get(fd)
            if not sk: return (-1, 9, b'')
            try:
                llevel, lname = translate_sockopt(level, optname)
                val = sk.getsockopt(llevel, lname, max(4, min(maxlen, 256)))
                # SO_ERROR comes back as little-endian on Linux but Amiga expects
                # the int value as a LONG.  Just preserve raw bytes; for SO_ERROR
                # also translate via to_bsd_errno.
                if level == _AMIGA_SOL_SOCKET and optname == 0x1007:
                    (errno_val,) = struct.unpack('<i', val[:4])
                    val = struct.pack('>i', to_bsd_errno(errno_val))
                # outdata = optlen(2) optval[optlen]
                out = struct.pack('>H', len(val)) + val
                return (0, 0, out)
            except OSError as e:
                return (-1, to_bsd_errno(e.errno or 0), b'')

        elif opcode == BSDOP_SETSOCKOPT:
            # args: fd(2) level(2) optname(2) optlen(2)
            # inlen = optlen (the option value bytes)
            (fd, level, optname, optlen) = struct.unpack_from('>HHHH', args)
            sk = sess.sockets.get(fd)
            if not sk: return (-1, 9, b'')
            try:
                llevel, lname = translate_sockopt(level, optname)
                sk.setsockopt(llevel, lname, indata)
                return (0, 0, b'')
            except OSError as e:
                return (-1, to_bsd_errno(e.errno or 0), b'')

        elif opcode == BSDOP_GETSOCKNAME or opcode == BSDOP_GETPEERNAME:
            (fd,) = struct.unpack_from('>H', args)
            sk = sess.sockets.get(fd)
            if not sk: return (-1, 9, b'')
            try:
                peer = (sk.getsockname() if opcode == BSDOP_GETSOCKNAME
                        else sk.getpeername())
                ip, port = peer[0], peer[1]
                sockaddr = (struct.pack('>HH', socket.AF_INET, port)
                            + socket.inet_aton(ip)
                            + b'\x00' * 8)
                out = struct.pack('>B', 16) + sockaddr
                return (0, 0, out)
            except OSError as e:
                return (-1, to_bsd_errno(e.errno or 0), b'')

        elif opcode == BSDOP_BIND:
            # args: fd(2) addrlen(1) addr[addrlen]
            (fd, alen) = struct.unpack_from('>HB', args)
            addr_bytes = args[3:3+alen]
            (_fam, port) = struct.unpack_from('>HH', addr_bytes)
            ip = socket.inet_ntoa(addr_bytes[4:8])
            sk = sess.sockets.get(fd)
            if not sk: return (-1, 9, b'')
            try:
                sk.bind((ip, port))
                return (0, 0, b'')
            except OSError as e:
                return (-1, to_bsd_errno(e.errno or 0), b'')

        elif opcode == BSDOP_LISTEN:
            (fd, backlog) = struct.unpack_from('>HH', args)
            sk = sess.sockets.get(fd)
            if not sk: return (-1, 9, b'')
            try:
                sk.listen(backlog)
                return (0, 0, b'')
            except OSError as e:
                return (-1, to_bsd_errno(e.errno or 0), b'')

        elif opcode == BSDOP_ACCEPT:
            (fd,) = struct.unpack_from('>H', args)
            sk = sess.sockets.get(fd)
            if not sk: return (-1, 9, b'')
            try:
                new_sk, peer = sk.accept()
                new_fd = sess.alloc_fd(new_sk)
                ip, port = peer[0], peer[1]
                sockaddr = (struct.pack('>HH', socket.AF_INET, port)
                            + socket.inet_aton(ip)
                            + b'\x00' * 8)
                out = struct.pack('>B', 16) + sockaddr
                return (new_fd, 0, out)
            except OSError as e:
                return (-1, to_bsd_errno(e.errno or 0), b'')

        elif opcode == BSDOP_GETHOSTBYADDR:
            (alen,) = struct.unpack_from('>B', args)
            ip_bytes = args[1:1+alen]
            ip = socket.inet_ntoa(ip_bytes) if alen == 4 else None
            try:
                hostname, _aliases, _ip = socket.gethostbyaddr(ip)
                return (0, 0, hostname.encode('ascii', 'replace'))
            except Exception:
                return (-1, 1, b'')

        elif opcode == BSDOP_SHUTDOWN:
            (fd, how) = struct.unpack_from('>HH', args)
            sk = sess.sockets.get(fd)
            if not sk: return (-1, 9, b'')
            try:
                sk.shutdown(how)
                return (0, 0, b'')
            except OSError as e:
                return (-1, to_bsd_errno(e.errno or 0), b'')

        elif opcode == BSDOP_GETHOSTBYNAME:
            (nlen,) = struct.unpack_from('>B', args)
            name = args[1:1+nlen].decode('ascii', 'replace')
            try:
                infos = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
                addrs = list(dict.fromkeys(i[4][0] for i in infos))  # de-dup, keep order
                if not addrs:
                    return (0, 1, b'')
                # Build 31: CAP to 4 addresses.  The Amiga a314bsd bsd_gethostbyname uses a
                # fixed 16-byte stack buffer (UBYTE addr_buf[16] = 4 IPv4 addrs) and only
                # ever uses the first address.  Hosts like www.google.com return 8 addrs
                # (32 bytes), which overflowed that stack buffer -> task stack smash ->
                # session RST -> iBrowse "host lookup failed, no DNS entry found".
                addrs = addrs[:4]
                out = b''.join(socket.inet_aton(a) for a in addrs)
                return (len(addrs), 0, out)
            except OSError as e:
                return (0, to_bsd_errno(e.errno or 1), b'')
            except Exception:
                return (0, 1, b'')

        elif opcode == BSDOP_WAITSELECT:
            import select
            (nfds, rm, wm, em, tv_sec, tv_usec) = struct.unpack_from('>HIIIII', args)
            timeout = None if tv_sec == 0xffffffff else (tv_sec + tv_usec/1e6)
            rfds = [sess.sockets[i] for i in range(nfds) if (rm >> i) & 1 and i in sess.sockets]
            wfds = [sess.sockets[i] for i in range(nfds) if (wm >> i) & 1 and i in sess.sockets]
            efds = [sess.sockets[i] for i in range(nfds) if (em >> i) & 1 and i in sess.sockets]
            # TLS-aware select: an SSLSocket can hold already-decrypted plaintext
            # inside OpenSSL that the raw-socket select() will NOT flag as readable
            # (the encrypted bytes were already pulled off the kernel socket by a
            # prior SSL_read of a whole TLS record).  Clients that drive their read
            # loop off select()/FIONREAD (AWeb) would otherwise stop reading and
            # truncate the response.  Force such sockets readable immediately.
            ssl_ready = []
            for s in rfds:
                if isinstance(s, _ssl.SSLSocket):
                    try:
                        if s.pending() > 0:
                            ssl_ready.append(s)
                    except Exception:
                        pass
            sel_timeout = 0 if ssl_ready else timeout
            try:
                rr, ww, ee = select.select(rfds, wfds, efds, sel_timeout)
            except OSError as e:
                return (-1, to_bsd_errno(e.errno or 0), b'')
            for s in ssl_ready:
                if s not in rr:
                    rr.append(s)
            def mask(socks):
                out = 0
                for s in socks:
                    for fd, sk in sess.sockets.items():
                        if sk is s:
                            out |= (1 << fd)
                return out
            rm_out = mask(rr)
            wm_out = mask(ww)
            em_out = mask(ee)
            n = bin(rm_out).count('1') + bin(wm_out).count('1') + bin(em_out).count('1')
            return (n, 0, struct.pack('>III', rm_out, wm_out, em_out))

        elif opcode == BSDOP_IOCTL:
            (fd, req, arg) = struct.unpack_from('>HII', args)
            sk = sess.sockets.get(fd)
            if not sk: return (-1, 9, b'')
            if req == 0x8004667e:   # FIONBIO
                sk.setblocking(arg == 0)
                return (0, 0, b'')
            elif req == 0x4004667f: # FIONREAD
                # TLS-aware FIONREAD: if this fd is an SSLSocket with already-
                # decrypted plaintext buffered inside OpenSSL, the raw-socket
                # FIONREAD reports 0 even though SSL_read can still return data.
                # Report pending() so select()/FIONREAD-driven clients (AWeb) keep
                # reading the rest of the response instead of truncating it.
                if isinstance(sk, _ssl.SSLSocket):
                    try:
                        pend = sk.pending()
                    except Exception:
                        pend = 0
                    if pend > 0:
                        return (pend, 0, b'')
                import fcntl, termios
                try:
                    n = fcntl.ioctl(sk.fileno(), termios.FIONREAD, b'\0\0\0\0')
                    return (struct.unpack('>I', n)[0], 0, b'')
                except OSError as e:
                    return (-1, to_bsd_errno(e.errno or 0), b'')
            return (-1, 22, b'')

        elif opcode >= BSDOP_SSL_CTX_NEW:
            return _ssl_dispatch(sess, opcode, args, indata)

        else:
            log.warning('unimplemented opcode %d', opcode)
            return (-1, 22, b'')   # EINVAL

    except Exception:
        log.exception('dispatch_op opcode=%d failed', opcode)
        return (-1, 5, b'')        # EIO

# ---------------------------------------------------------------------------
# a314d service plumbing
# ---------------------------------------------------------------------------

class A314Service:
    """Connects to a314d, registers the 'bsdsocket' service, multiplexes
    incoming streams.  Each stream gets its own Session and runs its own
    request-handling coroutine (so blocking ops in one don't stall others).

    Two startup modes:
      - Standalone (`bsdsocket.py` with no args): open localhost:7110,
        register the bsdsocket service ourselves
      - On-demand (a314d spawns us with `-ondemand <fd>`): use that socket
        fd, service is already pre-registered by a314d, MSG_CONNECT for
        the triggering Amiga stream is already queued in fd"""

    def __init__(self, reader=None, writer=None, do_register=True):
        self.reader = reader
        self.writer = writer
        self.do_register = do_register
        self.sessions = {}      # stream_id -> Session
        self.session_lock = asyncio.Lock()

    async def run(self):
        if self.reader is None:
            self.reader, self.writer = await asyncio.open_connection(A314D_HOST, A314D_PORT)
        if self.do_register:
            await self._register()
            log.warning('a314bsd v4.53 ready (standalone) on service %s', SERVICE_NAME.decode())
        else:
            log.warning('a314bsd v4.53 ready (on-demand) on service %s', SERVICE_NAME.decode())
        await self._read_loop()

    async def _register(self):
        # a314d REGISTER: pack header + service name
        pkt = struct.pack('=IIB', len(SERVICE_NAME), 0, MSG_REGISTER_REQ) + SERVICE_NAME
        self.writer.write(pkt)
        await self.writer.drain()
        hdr = await self.reader.readexactly(9)
        plen, sid, mtype = struct.unpack('=IIB', hdr)
        _resp = await self.reader.readexactly(plen) if plen else b''
        if mtype != MSG_REGISTER_RES:
            raise RuntimeError(f'registration failed: msg={mtype}')

    async def _read_loop(self):
        while True:
            hdr = await self.reader.readexactly(9)
            plen, sid, mtype = struct.unpack('=IIB', hdr)
            payload = await self.reader.readexactly(plen) if plen else b''

            if mtype == MSG_CONNECT:
                # New stream — accept and spawn handler.
                # CONNECT_RESPONSE format: 1-byte status (0 = accept).
                # plen=1, payload=1 byte.  Header is plen(4)+sid(4)+mtype(1).
                self.writer.write(struct.pack('=IIBB', 1, sid, MSG_CONNECT_RESPONSE, 0))
                await self.writer.drain()
                sess = Session(self, sid)
                self.sessions[sid] = sess
                log.warning('session %d opened (total open: %d)',
                            sid, len(self.sessions))
                asyncio.ensure_future(self._stream_handler(sess))

            elif mtype == MSG_DATA:
                sess = self.sessions.get(sid)
                if sess:
                    log.warning('session %d MSG_DATA %d bytes', sid, len(payload))
                    sess.rx_buffer.extend(payload)
                    if hasattr(sess, '_data_event'):
                        sess._data_event.set()

            elif mtype == MSG_EOS or mtype == MSG_RESET:
                sess = self.sessions.pop(sid, None)
                if sess:
                    log.warning('session %d closed (%s) after %d ops',
                                sid, 'EOS' if mtype == MSG_EOS else 'RST',
                                getattr(sess, '_op_count', 0))
                    sess.close_all()
                    if hasattr(sess, '_data_event'):
                        sess._data_event.set()    # wake handler so it exits
                if mtype == MSG_EOS:
                    self.writer.write(struct.pack('=IIB', 0, sid, MSG_EOS))
                    await self.writer.drain()

    async def _stream_handler(self, sess: Session):
        """Per-stream request loop.  Reads REQs, calls dispatch_op, writes RES.
        Runs in its own coroutine so a blocking op (recv/connect) in one
        stream doesn't stall others."""
        sess._data_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        try:
            while sess.stream_id in self.sessions:
                # Read REQ header (6 bytes) from rx buffer
                while len(sess.rx_buffer) < REQ_HDR_SIZE:
                    sess._data_event.clear()
                    await sess._data_event.wait()
                    if sess.stream_id not in self.sessions:
                        return
                hdr_bytes = bytes(sess.rx_buffer[:REQ_HDR_SIZE])
                opcode, seq, arglen, inlen = _REQ_HDR.unpack(hdr_bytes)
                needed = REQ_HDR_SIZE + arglen + inlen
                while len(sess.rx_buffer) < needed:
                    sess._data_event.clear()
                    await sess._data_event.wait()
                    if sess.stream_id not in self.sessions:
                        return
                args   = bytes(sess.rx_buffer[REQ_HDR_SIZE:REQ_HDR_SIZE+arglen])
                indata = bytes(sess.rx_buffer[REQ_HDR_SIZE+arglen:needed])
                del sess.rx_buffer[:needed]

                # Run dispatch in a thread for blocking ops so we don't stall
                # the asyncio event loop.
                result, errno_val, outdata = await loop.run_in_executor(
                    None, dispatch_op, sess, opcode, args, indata)

                # Write RES header
                self._send_chunk(sess.stream_id,
                                 encode_res_hdr(seq, result, errno_val, len(outdata)))
                # Then stream outdata in MAX_CHUNK-sized pieces
                off = 0
                while off < len(outdata):
                    self._send_chunk(sess.stream_id, outdata[off:off+MAX_CHUNK])
                    off += MAX_CHUNK
                await self.writer.drain()
        except asyncio.IncompleteReadError:
            pass
        except Exception:
            log.exception('stream handler [%d] crashed', sess.stream_id)
        finally:
            self.sessions.pop(sess.stream_id, None)
            sess.close_all()

    def _send_chunk(self, sid: int, data: bytes):
        # a314d DATA: header (plen, sid, mtype) + payload
        hdr = struct.pack('=IIB', len(data), sid, MSG_DATA)
        self.writer.write(hdr + data)

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

async def amain():
    """Async main: supports both standalone and on-demand startup modes."""
    # On-demand: a314d invoked us with `-ondemand <fd>` where <fd> is a
    # connected socket and the bsdsocket service is already pre-registered.
    try:
        idx = sys.argv.index('-ondemand')
        fd  = int(sys.argv[idx + 1])
        sock = socket.socket(fileno=fd)
        sock.setblocking(False)
        reader, writer = await asyncio.open_connection(sock=sock)
        svc = A314Service(reader=reader, writer=writer, do_register=False)
        await svc.run()
    except ValueError:
        # No `-ondemand` in argv — standalone mode.
        svc = A314Service()
        await svc.run()

def main():
    if '-d' in sys.argv or '--debug' in sys.argv:
        log.setLevel(logging.DEBUG)
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        log.warning('shutting down')

if __name__ == '__main__':
    main()
