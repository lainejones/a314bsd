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
import os
import socket
import struct
import sys
from typing import Optional, Tuple

# Network on/off flag, toggled by bsdctl.py (bsdnet stop/start, or the GUI).
# When present, new connect() calls are refused with ENETDOWN.  Same path as
# bsdctl.py (both scripts live in /opt/a314).
_PAUSE_FLAG = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           'bsdsocket.paused')

def _network_paused():
    return os.path.exists(_PAUSE_FLAG)

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
    114: 37,   # EALREADY
    115: 36,   # EINPROGRESS (non-blocking connect; raw 115 confused
               # select-driven clients — ported from fix branch)
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
        self.sockets = {}             # fd -> socket.socket (0/1/2 reserved)
        self.rx_buffer = bytearray()  # bytes received from a314d, not yet parsed
        # SOCK_RAW or SOCK_DGRAM+ICMP fds — recvfrom uses 1-sec timeout
        # (returns EINTR on timeout so ping can send next echo)
        self.raw_fds = set()
        # SOCK_DGRAM+ICMP fds that need synthesised IPv4 header on recvfrom
        # (Linux strips the IP header from SOCK_DGRAM_ICMP receives; the
        # Amiga ping app expects to see the IP header it would get from RAW)
        self.dgram_icmp_fds = set()

    # ---- socket table ----

    def alloc_fd(self, sock):
        # Reuse the LOWEST free fd (>= 3).  fds must stay < 32 because the
        # Amiga side carries fd_sets as 32-bit masks in WAITSELECT — the old
        # monotonic counter sailed past fd 31 after ~29 sockets in one
        # session, after which WaitSelect silently dropped those fds and
        # long browser sessions degraded/hung (fix ported from
        # fix/rpc-ret-and-fd-overflow, adapted to v5).
        fd = 3
        while fd in self.sockets:
            fd += 1
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
           22:'WAITSELECT', 23:'GETHOSTNAME', 24:'IOCTL'}

def dispatch_op(sess: Session, opcode: int, args: bytes, indata: bytes) -> Tuple[int, int, bytes]:
    """Execute one Amiga library call.  Returns (result, errno_val, outdata).
    Blocking ops (connect/recv/accept/waitselect) BLOCK the caller's a314d
    handler thread — that's fine because each Session has its own queue."""
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
            # Network on/off: if paused via bsdctl (bsdnet stop / the GUI),
            # refuse new connections with ENETDOWN.  Existing sockets are
            # untouched, so open connections keep working.
            if _network_paused():
                return (-1, 50, b'')   # ENETDOWN (AmiTCP)
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
                addrs = list({i[4][0] for i in infos})  # de-dup
                if not addrs:
                    return (0, 1, b'')
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
            try:
                rr, ww, ee = select.select(rfds, wfds, efds, timeout)
            except OSError as e:
                return (-1, to_bsd_errno(e.errno or 0), b'')
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
                import fcntl, termios
                try:
                    n = fcntl.ioctl(sk.fileno(), termios.FIONREAD, b'\0\0\0\0')
                    return (struct.unpack('>I', n)[0], 0, b'')
                except OSError as e:
                    return (-1, to_bsd_errno(e.errno or 0), b'')
            return (-1, 22, b'')

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
                asyncio.ensure_future(self._stream_handler(sess))

            elif mtype == MSG_DATA:
                sess = self.sessions.get(sid)
                if sess:
                    sess.rx_buffer.extend(payload)
                    if hasattr(sess, '_data_event'):
                        sess._data_event.set()

            elif mtype == MSG_EOS or mtype == MSG_RESET:
                sess = self.sessions.pop(sid, None)
                if sess:
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
