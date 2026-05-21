#!/usr/bin/env python3
"""
bsdsocket.py - a314BSD Pi service

Registers with a314d as "bsdsocket".  Each Amiga task that opens
bsdsocket.library connects as a separate stream (one per task).
Request packets arrive over that stream; the service executes the
corresponding socket syscall and sends a response.

Blocking calls (recv, connect, accept, waitselect) run in a thread
pool so they don't stall other streams.

Requires Python 3.7+ and asyncio.
"""

import asyncio
import socket
import struct
import logging
import sys
import select as _select
import concurrent.futures

logging.basicConfig(format='%(levelname)s %(asctime)s %(name)s:%(lineno)d: %(message)s')
log = logging.getLogger('bsdsocket')
log.setLevel(logging.DEBUG)   # TEMP: diagnosing download speed display bug

A314D_HOST   = 'localhost'
A314D_PORT   = 7110
SERVICE_NAME = b'bsdsocket'
CTL_NAME     = b'bsdctl'

# bsdctl single-byte command codes (Amiga → Pi)
CTL_QUERY  = 0x01
CTL_PAUSE  = 0x02
CTL_RESUME = 0x03

# bsdctl single-byte response codes (Pi → Amiga)
CTL_RUNNING = 0x01
CTL_PAUSED  = 0x02
CTL_OK      = 0x03

# ---- a314d message types ---------------------------------------------------

MSG_REGISTER_REQ     = 1
MSG_REGISTER_RES     = 2
MSG_CONNECT          = 9
MSG_CONNECT_RESPONSE = 10
MSG_DATA             = 11
MSG_EOS              = 12
MSG_RESET            = 13

# ---- BSD opcodes (must match include/bsd_proto.h) --------------------------

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

# ---- IoctlSocket request codes (from Amiga sys/socket.h) ------------------

FIONREAD = 0x4004667f
FIONBIO  = 0x8004667e

# ---- Socket option level/name translation: AmiTCP -> Linux -----------------
#
# AmiTCP (BSD4.4) uses SOL_SOCKET=0xffff; Linux uses SOL_SOCKET=1.
# SO_* option numbers also differ.  Translate the common ones so that calls
# like getsockopt(SOL_SOCKET, SO_ERROR) work correctly through the proxy.

_AMIGA_SOL_SOCKET = 0xffff   # AmiTCP SOL_SOCKET
_LINUX_SOL_SOCKET = socket.SOL_SOCKET  # = 1

# AmiTCP SO_* -> Linux SO_*  (only the common ones needed in practice)
_AMIGA_TO_LINUX_SO = {
    0x0001: socket.SO_DEBUG,        # SO_DEBUG
    0x0002: socket.SO_ACCEPTCONN,   # SO_ACCEPTCONN
    0x0004: socket.SO_REUSEADDR,    # SO_REUSEADDR
    0x0008: socket.SO_KEEPALIVE,    # SO_KEEPALIVE
    0x0010: socket.SO_DONTROUTE,    # SO_DONTROUTE
    0x0020: socket.SO_BROADCAST,    # SO_BROADCAST
    0x0080: socket.SO_LINGER,       # SO_LINGER
    0x0100: socket.SO_OOBINLINE,    # SO_OOBINLINE
    0x1001: socket.SO_SNDBUF,       # SO_SNDBUF
    0x1002: socket.SO_RCVBUF,       # SO_RCVBUF
    0x1003: socket.SO_SNDLOWAT,     # SO_SNDLOWAT
    0x1004: socket.SO_RCVLOWAT,     # SO_RCVLOWAT
    0x1005: socket.SO_SNDTIMEO,     # SO_SNDTIMEO
    0x1006: socket.SO_RCVTIMEO,     # SO_RCVTIMEO
    0x1007: socket.SO_ERROR,        # SO_ERROR
    0x1008: socket.SO_TYPE,         # SO_TYPE
}

def translate_sockopt(level, optname):
    """Translate AmiTCP SOL_SOCKET + SO_* constants to Linux equivalents."""
    if level == _AMIGA_SOL_SOCKET:
        return _LINUX_SOL_SOCKET, _AMIGA_TO_LINUX_SO.get(optname, optname)
    return level, optname

# ---- message flag translation: AmiTCP -> Linux -----------------------------
#
# Low bits (OOB=1, PEEK=2, DONTROUTE=4, EOR=8, TRUNC=16, CTRUNC=32) are the
# same on both.  The two that differ:
#   MSG_WAITALL:  AmiTCP 0x0040  vs  Linux 0x0100
#   MSG_DONTWAIT: AmiTCP 0x0080  vs  Linux 0x0040
# Passing AmiTCP values straight to Linux means MSG_WAITALL (0x40) looks like
# Linux MSG_DONTWAIT (0x40) — non-blocking — exactly the opposite of intended.

_AMIGA_MSG_WAITALL  = 0x0040
_AMIGA_MSG_DONTWAIT = 0x0080
_AMIGA_MSG_LOWBITS  = 0x003F   # bits identical between AmiTCP and Linux

def translate_msgflags(amiga_flags):
    """Translate AmiTCP MSG_* flags to Linux MSG_* flags."""
    linux_flags  = amiga_flags & _AMIGA_MSG_LOWBITS
    if amiga_flags & _AMIGA_MSG_WAITALL:
        linux_flags |= socket.MSG_WAITALL    # 0x0100 on Linux
    if amiga_flags & _AMIGA_MSG_DONTWAIT:
        linux_flags |= socket.MSG_DONTWAIT   # 0x0040 on Linux
    return linux_flags

# ---- errno translation: Linux -> BSD/AmiTCP --------------------------------
#
# errno values 1-34 are identical between Linux and BSD.
# The socket-specific range diverges at 35+.

_LINUX_TO_BSD = {
    11:  35,   # EAGAIN / EWOULDBLOCK
    36:  63,   # ENAMETOOLONG
    39:  66,   # ENOTEMPTY
    40:  62,   # ELOOP          (Linux=40,  BSD=62)
    88:  38,   # ENOTSOCK
    89:  39,   # EDESTADDRREQ
    90:  40,   # EMSGSIZE
    91:  41,   # EPROTOTYPE
    92:  42,   # ENOPROTOOPT
    93:  43,   # EPROTONOSUPPORT
    94:  44,   # ESOCKTNOSUPPORT
    95:  45,   # EOPNOTSUPP
    96:  46,   # EPFNOSUPPORT
    97:  47,   # EAFNOSUPPORT
    98:  48,   # EADDRINUSE
    99:  49,   # EADDRNOTAVAIL
    100: 50,   # ENETDOWN
    101: 51,   # ENETUNREACH
    102: 52,   # ENETRESET
    103: 53,   # ECONNABORTED
    104: 54,   # ECONNRESET
    105: 55,   # ENOBUFS
    106: 56,   # EISCONN
    107: 57,   # ENOTCONN
    108: 58,   # ESHUTDOWN
    109: 59,   # ETOOMANYREFS
    110: 60,   # ETIMEDOUT
    111: 61,   # ECONNREFUSED
    112: 64,   # EHOSTDOWN
    113: 65,   # EHOSTUNREACH
    114: 37,   # EALREADY       (Linux=114, BSD=37)
    115: 36,   # EINPROGRESS    (Linux=115, BSD=36)
}

def to_bsd_errno(linux_errno):
    return _LINUX_TO_BSD.get(linux_errno, linux_errno)

# ---- sockaddr encode/decode ------------------------------------------------
#
# Two sockaddr_in layouts exist in the Amiga world:
#
#   AmiTCP (no sin_len):
#     sin_family(2BE)  sin_port(2BE)  sin_addr(4)  sin_zero(8)   = 16 bytes
#     bytes[0:2] = 0x0002 when AF_INET
#
#   BSD4.4 (with sin_len, used by e.g. smb2fs/libsmb2):
#     sin_len(1)  sin_family(1)  sin_port(2BE)  sin_addr(4)  sin_zero(8) = 16 bytes
#     bytes[0] = 0x10 (16), bytes[1] = 0x02 (AF_INET)
#
# Detection: if data[0] >= 2 and data[1] == AF_INET → BSD4.4, else AmiTCP.
# (AmiTCP has data[0]=0 as the high byte of AF_INET=2.)

def _sockaddr_has_sinlen(data):
    """True if sockaddr uses BSD4.4 sin_len prefix."""
    return len(data) >= 2 and data[0] >= 2 and data[1] == socket.AF_INET

def decode_sockaddr(data):
    """Amiga big-endian sockaddr_in bytes -> (host, port) or None."""
    if len(data) < 8:
        return None
    if _sockaddr_has_sinlen(data):
        # BSD4.4: sin_len(1), sin_family(1), sin_port(2), sin_addr(4)
        if data[1] != socket.AF_INET:
            return None
        port = struct.unpack('>H', data[2:4])[0]
        offset = 4
    else:
        # AmiTCP: sin_family(2), sin_port(2), sin_addr(4)
        family = struct.unpack('>H', data[0:2])[0]
        if family != socket.AF_INET:
            return None
        port = struct.unpack('>H', data[2:4])[0]
        offset = 4
    try:
        addr = socket.inet_ntoa(data[offset:offset + 4])
    except Exception:
        return None
    return (addr, port)

def encode_sockaddr(sa, sin_len=False):
    """Python (host, port) -> Amiga big-endian sockaddr_in bytes (16 bytes).
    sin_len=True produces BSD4.4 format; False produces AmiTCP format."""
    try:
        host, port = sa[0], sa[1]
        ab = socket.inet_aton(host)
        if sin_len:
            return struct.pack('>BBH', 16, socket.AF_INET, port) + ab + b'\x00' * 8
        else:
            return struct.pack('>HH', socket.AF_INET, port) + ab + b'\x00' * 8
    except Exception:
        return b''

# ---- Per-stream session ----------------------------------------------------

class Session:
    def __init__(self, stream_id, svc):
        self.stream_id   = stream_id
        self.svc         = svc           # back-ref for write()
        self.sockets     = {}            # amiga_fd -> socket.socket
        self.nonblock    = set()         # fds set non-blocking
        self.raw_fds      = set()         # fds that are SOCK_RAW (ping etc.)
        self.dgram_icmp_fds = set()      # SOCK_DGRAM+ICMP fds emulating SOCK_RAW
                                         # (used when SOCK_RAW fails with EPERM;
                                         #  recvfrom prepends a synthesised IP hdr)
        self.sin_len_fmt  = False        # True = BSD4.4 sin_len; False = AmiTCP
        self.recv_totals = {}            # fd -> cumulative bytes delivered via recv

    def alloc_fd(self, sock):
        # Always reuse the lowest available fd so that fds stay small (1-31)
        # and never overflow the Amiga's 32-bit fd_set bitmask.  A monotonic
        # high-water mark would exceed fd=31 after ~32 connections and cause
        # WaitSelect to silently drop the fd from its select() call.
        fd = 1
        while fd in self.sockets:
            fd += 1
        self.sockets[fd] = sock
        return fd

    def get(self, fd):
        return self.sockets.get(fd)

    def close_all(self):
        for sock in self.sockets.values():
            try: sock.close()
            except Exception: pass
        self.sockets.clear()
        self.raw_fds.clear()
        self.dgram_icmp_fds.clear()
        self.recv_totals.clear()

    async def send(self, seq, result, data=b''):
        # Mask result to 32 bits so negative errno values pack as unsigned int.
        payload = struct.pack('>BIH', seq, result & 0xFFFFFFFF, len(data)) + data
        frame   = struct.pack('=IIB', len(payload), self.stream_id, MSG_DATA) + payload
        await self.svc.write(frame)

    async def run_blocking(self, fn, *args):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self.svc.executor, fn, *args)

    # ---- opcode handlers ---------------------------------------------------

    async def op_socket(self, seq, args):
        if len(args) < 6:
            return await self.send(seq, -22)
        domain, typ, proto = struct.unpack('>HHH', args[:6])
        dgram_icmp = False
        def _do():
            nonlocal dgram_icmp
            try:
                sock = socket.socket(domain, typ, proto)
            except PermissionError:
                # SOCK_RAW requires CAP_NET_RAW; fall back to SOCK_DGRAM for
                # ICMP (Linux "ping sockets", allowed by default on RPi OS via
                # net.ipv4.ping_group_range = 0 2147483647).
                # recvfrom will prepend a synthesised IP header so the Amiga
                # app sees the same layout as a real SOCK_RAW receive.
                if typ == socket.SOCK_RAW and proto == 1:  # IPPROTO_ICMP=1
                    sock = socket.socket(domain, socket.SOCK_DGRAM, proto)
                    dgram_icmp = True
                else:
                    raise
            sock.setblocking(True)
            return sock
        try:
            sock = await self.run_blocking(_do)
        except OSError as e:
            return await self.send(seq, -to_bsd_errno(e.errno))
        fd = self.alloc_fd(sock)
        # Raw sockets (SOCK_RAW or SOCK_DGRAM fallback for ICMP) are used for
        # ping-like tools.  In real AmiTCP a timer signal interrupts blocking
        # recvfrom with EINTR so the app can send the next echo request.  Our
        # proxy can't receive Amiga signals, so we impose a 1-second internal
        # timeout and return EINTR, which has the same effect.
        if typ == socket.SOCK_RAW or dgram_icmp:
            sock.settimeout(1.0)
            self.raw_fds.add(fd)
            if dgram_icmp:
                self.dgram_icmp_fds.add(fd)
                log.debug('[%d] socket(%d,%d,%d) -> fd=%d (SOCK_DGRAM fallback for ICMP)',
                          self.stream_id, domain, typ, proto, fd)
            else:
                log.debug('[%d] socket(%d,%d,%d) -> fd=%d (SOCK_RAW)',
                          self.stream_id, domain, typ, proto, fd)
        else:
            log.debug('[%d] socket(%d,%d,%d) -> fd=%d', self.stream_id, domain, typ, proto, fd)
        await self.send(seq, fd)

    async def op_close(self, seq, args):
        if len(args) < 2:
            return await self.send(seq, -22)
        fd = struct.unpack('>H', args[:2])[0]
        sock = self.sockets.pop(fd, None)
        self.nonblock.discard(fd)
        self.raw_fds.discard(fd)
        self.dgram_icmp_fds.discard(fd)
        if sock:
            try: sock.close()
            except Exception: pass
        total = self.recv_totals.pop(fd, 0)
        log.debug('[%d] close(fd=%d) recv_total=%d', self.stream_id, fd, total)
        await self.send(seq, 0)

    async def op_connect(self, seq, args):
        if len(args) < 3:
            return await self.send(seq, -22)
        fd = struct.unpack('>H', args[:2])[0]
        addrlen = args[2]
        raw = args[3:3 + addrlen]
        if _sockaddr_has_sinlen(raw):
            self.sin_len_fmt = True
        sa = decode_sockaddr(raw)
        sock = self.get(fd)
        if not sock or not sa:
            log.warning('[%d] connect: bad fd or undecoded addr (sock=%s, sa=%s, raw=%s)',
                        self.stream_id, sock, sa, raw.hex())
            return await self.send(seq, -9)
        try:
            await self.run_blocking(sock.connect, sa)
            log.debug('[%d] connect(fd=%d, %s) -> OK', self.stream_id, fd, sa)
            await self.send(seq, 0)
        except OSError as e:
            if e.errno == 115:  # EINPROGRESS — non-blocking connect started
                # Return EINPROGRESS immediately.  The caller (AmiSpeedTest
                # openConnection) then calls WaitSelect to wait for writability,
                # which our op_waitselect handles via select() on the Pi socket.
                # The Pi socket is already connecting in the background; select
                # will return it writable once the TCP handshake completes.
                log.debug('[%d] connect(fd=%d, %s) -> EINPROGRESS (non-blocking)',
                          self.stream_id, fd, sa)
                await self.send(seq, -36)  # BSD EINPROGRESS
                return
            log.debug('[%d] connect(fd=%d, %s) -> OSError errno=%d (%s)',
                      self.stream_id, fd, sa, e.errno, e.strerror)
            await self.send(seq, -to_bsd_errno(e.errno))

    async def op_bind(self, seq, args):
        if len(args) < 3:
            return await self.send(seq, -22)
        fd = struct.unpack('>H', args[:2])[0]
        addrlen = args[2]
        raw = args[3:3 + addrlen]
        if _sockaddr_has_sinlen(raw):
            self.sin_len_fmt = True
        sa = decode_sockaddr(raw)
        sock = self.get(fd)
        if not sock or not sa:
            return await self.send(seq, -9)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(sa)
            await self.send(seq, 0)
        except OSError as e:
            await self.send(seq, -to_bsd_errno(e.errno))

    async def op_listen(self, seq, args):
        if len(args) < 4:
            return await self.send(seq, -22)
        fd, backlog = struct.unpack('>HH', args[:4])
        sock = self.get(fd)
        if not sock:
            return await self.send(seq, -9)
        try:
            sock.listen(backlog)
            await self.send(seq, 0)
        except OSError as e:
            await self.send(seq, -to_bsd_errno(e.errno))

    async def op_accept(self, seq, args):
        if len(args) < 2:
            return await self.send(seq, -22)
        fd = struct.unpack('>H', args[:2])[0]
        sock = self.get(fd)
        if not sock:
            return await self.send(seq, -9)
        try:
            conn, addr = await self.run_blocking(sock.accept)
            conn.setblocking(True)
            new_fd = self.alloc_fd(conn)
            ab = encode_sockaddr(addr, self.sin_len_fmt)
            log.debug('[%d] accept(fd=%d) -> new_fd=%d %s', self.stream_id, fd, new_fd, addr)
            await self.send(seq, new_fd, bytes([len(ab)]) + ab)
        except OSError as e:
            await self.send(seq, -to_bsd_errno(e.errno))

    async def op_send(self, seq, args):
        if len(args) < 6:
            return await self.send(seq, -22)
        fd, flags, datalen = struct.unpack('>HHH', args[:6])
        payload = args[6:6 + datalen]
        sock = self.get(fd)
        if not sock:
            return await self.send(seq, -9)
        flags = translate_msgflags(flags)
        try:
            n = await self.run_blocking(sock.send, payload, flags)
            log.debug('[%d] send(fd=%d) -> %d bytes', self.stream_id, fd, n)
            await self.send(seq, n)
        except OSError as e:
            log.debug('[%d] send OSError errno=%d: %s', self.stream_id, e.errno, e)
            await self.send(seq, -to_bsd_errno(e.errno))

    async def op_recv(self, seq, args):
        if len(args) < 6:
            return await self.send(seq, -22)
        fd, flags, maxlen = struct.unpack('>HHH', args[:6])
        flags = translate_msgflags(flags)
        log.debug('[%d] recv(fd=%d, maxlen=%d, flags=0x%x)', self.stream_id, fd, maxlen, flags)
        sock = self.get(fd)
        if not sock:
            log.warning('[%d] recv: fd %d not found in session', self.stream_id, fd)
            return await self.send(seq, -9)
        try:
            data = await self.run_blocking(sock.recv, maxlen, flags)
            self.recv_totals[fd] = self.recv_totals.get(fd, 0) + len(data)
            log.debug('[%d] recv fd=%d -> %d bytes (fd total: %d)',
                      self.stream_id, fd, len(data), self.recv_totals[fd])
            await self.send(seq, len(data), data)
        except socket.timeout:
            log.debug('[%d] recv timeout (SO_RCVTIMEO)', self.stream_id)
            await self.send(seq, -35)   # BSD EAGAIN — caller interprets as timeout
        except BlockingIOError:
            log.debug('[%d] recv EAGAIN (MSG_DONTWAIT, no data)', self.stream_id)
            await self.send(seq, -35)   # BSD EAGAIN
        except OSError as e:
            log.debug('[%d] recv OSError errno=%d: %s', self.stream_id, e.errno, e)
            await self.send(seq, -to_bsd_errno(e.errno))

    async def op_sendto(self, seq, args):
        if len(args) < 5:
            return await self.send(seq, -22)
        fd, flags = struct.unpack('>HH', args[:4])
        addrlen = args[4]
        raw = args[5:5 + addrlen]
        if _sockaddr_has_sinlen(raw):
            self.sin_len_fmt = True
        sa = decode_sockaddr(raw)
        rest = args[5 + addrlen:]
        if len(rest) < 2:
            return await self.send(seq, -22)
        datalen = struct.unpack('>H', rest[:2])[0]
        payload = rest[2:2 + datalen]
        sock = self.get(fd)
        if not sock:
            return await self.send(seq, -9)
        flags = translate_msgflags(flags)
        try:
            n = await self.run_blocking(sock.sendto, payload, flags, sa)
            await self.send(seq, n)
        except OSError as e:
            await self.send(seq, -to_bsd_errno(e.errno))

    async def op_recvfrom(self, seq, args):
        if len(args) < 6:
            return await self.send(seq, -22)
        fd, flags, maxlen = struct.unpack('>HHH', args[:6])
        flags = translate_msgflags(flags)
        log.debug('[%d] recvfrom(fd=%d, maxlen=%d, flags=0x%x)', self.stream_id, fd, maxlen, flags)
        sock = self.get(fd)
        if not sock:
            return await self.send(seq, -9)
        try:
            data, addr = await self.run_blocking(sock.recvfrom, maxlen, flags)
            if fd in self.dgram_icmp_fds:
                # SOCK_DGRAM+ICMP returns only the ICMP bytes (no IP header).
                # Prepend a synthesised 20-byte IPv4 header so the Amiga app
                # sees the same layout it would get from a real SOCK_RAW socket.
                # Source IP comes from recvfrom's addr tuple; TTL is faked (64).
                try:
                    src_ip = socket.inet_aton(addr[0])
                except OSError:
                    src_ip = b'\x00\x00\x00\x00'
                fake_iphdr = struct.pack('>BBHHHBBH4s4s',
                    0x45, 0,                   # Ver=4 IHL=5, DSCP/ECN=0
                    20 + len(data),            # Total length
                    0, 0,                      # ID, Flags+FragOff
                    64, 1, 0,                  # TTL=64, Proto=ICMP, Checksum=0
                    src_ip,                    # Source address
                    b'\x00\x00\x00\x00',       # Dest address (unknown, ignored by ping)
                )
                data = fake_iphdr + data
                log.debug('[%d] recvfrom dgram-icmp -> %d bytes (incl fake iphdr) from %s',
                          self.stream_id, len(data), addr)
            else:
                log.debug('[%d] recvfrom -> %d bytes from %s', self.stream_id, len(data), addr)
            ab = encode_sockaddr(addr, self.sin_len_fmt)
            await self.send(seq, len(data), data + bytes([len(ab)]) + ab)
        except socket.timeout:
            if fd in self.raw_fds:
                # Internal 1-second timeout on raw socket: simulate SIGALRM
                # interrupting a blocking recvfrom (how real AmiTCP ping works).
                log.debug('[%d] recvfrom raw timeout -> EINTR', self.stream_id)
                await self.send(seq, -4)    # BSD EINTR
            else:
                log.debug('[%d] recvfrom timeout (SO_RCVTIMEO)', self.stream_id)
                await self.send(seq, -35)   # BSD EAGAIN
        except BlockingIOError:
            log.debug('[%d] recvfrom EAGAIN (MSG_DONTWAIT, no data)', self.stream_id)
            await self.send(seq, -35)   # BSD EAGAIN
        except OSError as e:
            await self.send(seq, -to_bsd_errno(e.errno))

    async def op_setsockopt(self, seq, args):
        if len(args) < 8:
            return await self.send(seq, -22)
        fd, level, optname, optlen = struct.unpack('>HHHH', args[:8])
        optval = args[8:8 + optlen]
        sock = self.get(fd)
        if not sock:
            return await self.send(seq, -9)
        log.debug('[%d] setsockopt(fd=%d, level=0x%x, optname=0x%x, optlen=%d)',
                  self.stream_id, fd, level, optname, optlen)
        level, optname = translate_sockopt(level, optname)
        try:
            # SO_RCVTIMEO / SO_SNDTIMEO: the Amiga sends a big-endian timeval
            # (4 bytes tv_sec, or 8 bytes tv_sec+tv_usec). Linux setsockopt
            # expects a native struct timeval whose size varies by platform.
            # Use Python's sock.settimeout() which is platform-agnostic.
            if optname in (socket.SO_RCVTIMEO, socket.SO_SNDTIMEO):
                if optlen >= 8:
                    tv_sec, tv_usec = struct.unpack('>II', bytes(optval[:8]))
                elif optlen >= 4:
                    tv_sec  = struct.unpack('>I', bytes(optval[:4]))[0]
                    tv_usec = 0
                else:
                    return await self.send(seq, -22)
                timeout = (tv_sec + tv_usec / 1_000_000.0) if (tv_sec or tv_usec) else None
                sock.settimeout(timeout)
                log.debug('[%d] SO_%sTIMEO -> settimeout(%s)',
                          self.stream_id,
                          'RCV' if optname == socket.SO_RCVTIMEO else 'SND',
                          timeout)
                return await self.send(seq, 0)
            if optlen == 4:
                sock.setsockopt(level, optname, struct.unpack('>I', optval)[0])
            else:
                sock.setsockopt(level, optname, bytes(optval))
            await self.send(seq, 0)
        except OSError as e:
            await self.send(seq, -to_bsd_errno(e.errno))

    async def op_getsockopt(self, seq, args):
        if len(args) < 6:
            return await self.send(seq, -22)
        fd, level, optname = struct.unpack('>HHH', args[:6])
        sock = self.get(fd)
        if not sock:
            return await self.send(seq, -9)
        level, optname = translate_sockopt(level, optname)
        try:
            val = sock.getsockopt(level, optname, 256)
            if isinstance(val, int):
                val = struct.pack('>I', val)
            # SO_ERROR is a native little-endian int on the Pi; re-encode as
            # big-endian for the Amiga, and translate the Linux errno to BSD.
            if optname == socket.SO_ERROR and len(val) == 4:
                err = struct.unpack('<I', val)[0]
                if err:
                    err = to_bsd_errno(err)
                val = struct.pack('>I', err)
            await self.send(seq, 0, struct.pack('>H', len(val)) + val)
        except OSError as e:
            await self.send(seq, -to_bsd_errno(e.errno))

    async def op_shutdown(self, seq, args):
        if len(args) < 4:
            return await self.send(seq, -22)
        fd, how = struct.unpack('>HH', args[:4])
        sock = self.get(fd)
        if not sock:
            return await self.send(seq, -9)
        try:
            sock.shutdown(how)
            await self.send(seq, 0)
        except OSError as e:
            await self.send(seq, -to_bsd_errno(e.errno))

    async def _op_sockname(self, seq, args, peer):
        if len(args) < 2:
            return await self.send(seq, -22)
        fd = struct.unpack('>H', args[:2])[0]
        sock = self.get(fd)
        if not sock:
            return await self.send(seq, -9)
        try:
            sa = sock.getpeername() if peer else sock.getsockname()
            ab = encode_sockaddr(sa, self.sin_len_fmt)
            await self.send(seq, 0, bytes([len(ab)]) + ab)
        except OSError as e:
            await self.send(seq, -to_bsd_errno(e.errno))

    async def op_getsockname(self, seq, args):
        await self._op_sockname(seq, args, peer=False)

    async def op_getpeername(self, seq, args):
        await self._op_sockname(seq, args, peer=True)

    async def op_ioctl(self, seq, args):
        if len(args) < 10:
            return await self.send(seq, -22)
        fd = struct.unpack('>H', args[:2])[0]
        request, arg = struct.unpack('>II', args[2:10])
        log.debug('[%d] ioctl(fd=%d, request=0x%x, arg=0x%x)', self.stream_id, fd, request, arg)
        sock = self.get(fd)
        if not sock:
            return await self.send(seq, -9)
        try:
            if request == FIONBIO:
                sock.setblocking(arg == 0)
                if arg:
                    self.nonblock.add(fd)
                else:
                    self.nonblock.discard(fd)
                await self.send(seq, 0)
            elif request == FIONREAD:
                # How many bytes are readable without blocking.
                # Use MSG_PEEK so the data stays in the socket buffer.
                r, _, _ = _select.select([sock], [], [], 0)
                count = 0
                if r:
                    try:
                        data = sock.recv(65536, socket.MSG_PEEK | socket.MSG_DONTWAIT)
                        count = len(data)
                    except Exception:
                        count = 0
                await self.send(seq, count)
            else:
                await self.send(seq, -45)   # EOPNOTSUPP
        except OSError as e:
            await self.send(seq, -to_bsd_errno(e.errno))

    async def op_gethostbyname(self, seq, args):
        if not args:
            return await self.send(seq, -22)
        namelen = args[0]
        name = args[1:1 + namelen].decode('latin-1', errors='replace')
        def _resolve():
            infos = socket.getaddrinfo(name, None, socket.AF_INET,
                                       socket.SOCK_STREAM)
            seen = []
            for i in infos:
                a = i[4][0]
                if a not in seen:
                    seen.append(a)
            return seen
        try:
            addrs = await self.run_blocking(_resolve)
            addr_bytes = b''.join(socket.inet_aton(a) for a in addrs[:8])
            log.debug('[%d] gethostbyname(%s) -> %s', self.stream_id, name, addrs[:8])
            await self.send(seq, len(addrs[:8]), addr_bytes)
        except OSError as e:
            await self.send(seq, -to_bsd_errno(e.errno))

    async def op_gethostbyaddr(self, seq, args):
        if not args:
            return await self.send(seq, -22)
        addrlen = args[0]
        addr_bytes = args[1:1 + addrlen]
        if len(addr_bytes) < addrlen or len(args) < 1 + addrlen + 2:
            return await self.send(seq, -22)
        # type = struct.unpack('>H', args[1+addrlen:3+addrlen])[0]
        try:
            ip = socket.inet_ntoa(addr_bytes[:4])
            name = await self.run_blocking(socket.gethostbyaddr, ip)
            hostname = name[0].encode('latin-1')
            await self.send(seq, 0, hostname)
        except OSError as e:
            await self.send(seq, -to_bsd_errno(e.errno))

    async def op_inet_addr(self, seq, args):
        if not args:
            return await self.send(seq, -22)
        slen = args[0]
        s = args[1:1 + slen].decode('ascii', errors='replace')
        try:
            packed = socket.inet_aton(s)
            await self.send(seq, 0, packed)
        except OSError:
            await self.send(seq, -1)

    async def op_inet_ntoa(self, seq, args):
        if len(args) < 4:
            return await self.send(seq, -22)
        try:
            s = socket.inet_ntoa(bytes(args[:4])).encode('ascii')
            await self.send(seq, 0, s)
        except OSError:
            await self.send(seq, -1)

    async def op_getservbyname(self, seq, args):
        if not args:
            return await self.send(seq, -22)
        nl = args[0]
        name = args[1:1 + nl].decode('latin-1')
        pl = args[1 + nl] if len(args) > 1 + nl else 0
        proto = args[2 + nl:2 + nl + pl].decode('latin-1') if pl else None
        def _do():
            return socket.getservbyname(name, proto)
        try:
            port = await self.run_blocking(_do)
            proto_b = (proto or '').encode('latin-1')
            await self.send(seq, port, proto_b)
        except OSError as e:
            await self.send(seq, -to_bsd_errno(e.errno))

    async def op_getservbyport(self, seq, args):
        if len(args) < 3:
            return await self.send(seq, -22)
        port = struct.unpack('>H', args[:2])[0]
        pl = args[2]
        proto = args[3:3 + pl].decode('latin-1') if pl else None
        def _do():
            return socket.getservbyport(port, proto)
        try:
            name = await self.run_blocking(_do)
            await self.send(seq, port, name.encode('latin-1'))
        except OSError as e:
            await self.send(seq, -to_bsd_errno(e.errno))

    async def op_waitselect(self, seq, args):
        if len(args) < 22:
            return await self.send(seq, -22)
        nfds, rmask, wmask, emask, tv_sec, tv_usec = struct.unpack('>HIIIII', args[:22])
        timeout = None if tv_sec == 0xffffffff else tv_sec + tv_usec / 1_000_000

        rlist = [self.get(fd) for fd in range(nfds)
                 if (rmask >> fd) & 1 and self.get(fd)]
        wlist = [self.get(fd) for fd in range(nfds)
                 if (wmask >> fd) & 1 and self.get(fd)]
        xlist = [self.get(fd) for fd in range(nfds)
                 if (emask >> fd) & 1 and self.get(fd)]

        log.debug('[%d] WaitSelect nfds=%d rmask=0x%x wmask=0x%x emask=0x%x '
                  'timeout=%s rlist=%d wlist=%d xlist=%d',
                  self.stream_id, nfds, rmask, wmask, emask,
                  timeout, len(rlist), len(wlist), len(xlist))

        def _do():
            return _select.select(rlist, wlist, xlist, timeout)

        try:
            r, w, x = await self.run_blocking(_do)
        except OSError as e:
            return await self.send(seq, -to_bsd_errno(e.errno))

        def to_mask(ready):
            m = 0
            for fd, s in self.sockets.items():
                if s in ready:
                    m |= (1 << fd)
            return m

        nr = len(r) + len(w) + len(x)
        rm_out = to_mask(r)
        wm_out = to_mask(w)
        em_out = to_mask(x)
        log.debug('[%d] WaitSelect -> nr=%d rmask_out=0x%x wmask_out=0x%x emask_out=0x%x',
                  self.stream_id, nr, rm_out, wm_out, em_out)
        data = struct.pack('>III', rm_out, wm_out, em_out)
        await self.send(seq, nr, data)

    async def op_gethostname(self, seq, args):
        name = socket.gethostname().encode('latin-1')
        await self.send(seq, 0, name)

    # ---- dispatcher --------------------------------------------------------

    _OPS = None   # built lazily

    def _build_ops(self):
        return {
            BSDOP_SOCKET:        self.op_socket,
            BSDOP_CLOSE:         self.op_close,
            BSDOP_CONNECT:       self.op_connect,
            BSDOP_BIND:          self.op_bind,
            BSDOP_LISTEN:        self.op_listen,
            BSDOP_ACCEPT:        self.op_accept,
            BSDOP_SEND:          self.op_send,
            BSDOP_RECV:          self.op_recv,
            BSDOP_SENDTO:        self.op_sendto,
            BSDOP_RECVFROM:      self.op_recvfrom,
            BSDOP_SETSOCKOPT:    self.op_setsockopt,
            BSDOP_GETSOCKOPT:    self.op_getsockopt,
            BSDOP_SHUTDOWN:      self.op_shutdown,
            BSDOP_GETSOCKNAME:   self.op_getsockname,
            BSDOP_GETPEERNAME:   self.op_getpeername,
            BSDOP_GETHOSTBYNAME: self.op_gethostbyname,
            BSDOP_GETHOSTBYADDR: self.op_gethostbyaddr,
            BSDOP_INET_ADDR:     self.op_inet_addr,
            BSDOP_INET_NTOA:     self.op_inet_ntoa,
            BSDOP_GETSERVBYNAME: self.op_getservbyname,
            BSDOP_GETSERVBYPORT: self.op_getservbyport,
            BSDOP_WAITSELECT:    self.op_waitselect,
            BSDOP_GETHOSTNAME:   self.op_gethostname,
            BSDOP_IOCTL:         self.op_ioctl,
        }

    async def dispatch(self, payload):
        opcode = -1
        seq    = -1
        try:
            if len(payload) < 4:
                log.warning('[%d] short packet (%d bytes)', self.stream_id, len(payload))
                return
            opcode, seq, arglen = struct.unpack('>BBH', payload[:4])
            args = payload[4:4 + arglen]

            if self._OPS is None:
                self._OPS = self._build_ops()
            handler = self._OPS.get(opcode)
            if handler:
                await handler(seq, args)
            else:
                log.warning('[%d] unknown opcode %d seq=%d arglen=%d payload=%s',
                            self.stream_id, opcode, seq, arglen,
                            payload.hex())
                await self.send(seq, -45)   # EOPNOTSUPP
        except Exception:
            log.exception('[%d] dispatch unhandled exception (opcode=%d seq=%d)',
                          self.stream_id, opcode, seq)

# ---- a314d service ---------------------------------------------------------

class A314BsdService:
    def __init__(self, reader, writer):
        self.reader      = reader
        self.writer      = writer
        self.sessions    = {}
        self.ctl_streams = set()
        self.paused      = False
        self.executor    = concurrent.futures.ThreadPoolExecutor(
            max_workers=32, thread_name_prefix='bsd')
        self._wlock      = asyncio.Lock()

    async def write(self, data):
        async with self._wlock:
            self.writer.write(data)
            await self.writer.drain()

    async def _read_msg(self):
        hdr = await self.reader.readexactly(9)
        plen, stream_id, ptype = struct.unpack('=IIB', hdr)
        payload = await self.reader.readexactly(plen)
        return stream_id, ptype, payload

    async def _register_service(self, name):
        reg = struct.pack('=IIB', len(name), 0, MSG_REGISTER_REQ) + name
        await self.write(reg)
        stream_id, ptype, payload = await self._read_msg()
        if ptype != MSG_REGISTER_RES or payload[0] != 1:
            log.error('Failed to register "%s" with a314d', name.decode())
            return False
        log.info('Registered "%s" with a314d', name.decode())
        return True

    async def _handle_ctl(self, stream_id, payload):
        if not payload:
            return
        cmd = payload[0]
        if cmd == CTL_QUERY:
            rsp = CTL_PAUSED if self.paused else CTL_RUNNING
        elif cmd == CTL_PAUSE:
            self.paused = True
            log.info('bsdsocket paused by Amiga (new connections blocked)')
            rsp = CTL_OK
        elif cmd == CTL_RESUME:
            self.paused = False
            log.info('bsdsocket resumed by Amiga')
            rsp = CTL_OK
        else:
            rsp = CTL_OK
        await self.write(struct.pack('=IIB', 1, stream_id, MSG_DATA) + bytes([rsp]))
        await self.write(struct.pack('=IIB', 0, stream_id, MSG_EOS))
        self.ctl_streams.discard(stream_id)

    async def run(self, register=True):
        pending = []  # messages buffered during on-demand bsdctl registration

        if register is True:
            # Standalone mode: register both services ourselves.
            if not await self._register_service(SERVICE_NAME):
                return
            if not await self._register_service(CTL_NAME):
                return
        elif register == 'ondemand':
            # a314d launched us and already registered 'bsdsocket' on our behalf,
            # then immediately sent MSG_CONNECT for the triggering Amiga stream —
            # that MSG_CONNECT is already queued in the socket when we start.
            # Register 'bsdctl' ourselves; buffer anything that arrives before
            # MSG_REGISTER_RES so the main loop can process it afterwards.
            reg = struct.pack('=IIB', len(CTL_NAME), 0, MSG_REGISTER_REQ) + CTL_NAME
            await self.write(reg)
            while True:
                sid, pt, pay = await self._read_msg()
                if pt == MSG_REGISTER_RES:
                    if not pay or pay[0] != 1:
                        log.error('Failed to register "bsdctl" with a314d (on-demand)')
                        return
                    log.info('Registered "bsdctl" with a314d (on-demand)')
                    break
                pending.append((sid, pt, pay))

        while True:
            if pending:
                stream_id, ptype, payload = pending.pop(0)
            else:
                try:
                    stream_id, ptype, payload = await self._read_msg()
                except asyncio.IncompleteReadError:
                    log.error('a314d connection closed unexpectedly')
                    return
                except Exception:
                    log.exception('_read_msg failed')
                    return

            if ptype == MSG_CONNECT:
                if payload == CTL_NAME:
                    self.ctl_streams.add(stream_id)
                    await self.write(struct.pack('=IIBB', 1, stream_id,
                                                MSG_CONNECT_RESPONSE, 0))
                elif payload == SERVICE_NAME and not self.paused:
                    log.info('Amiga task connected (stream %d)', stream_id)
                    sess = Session(stream_id, self)
                    self.sessions[stream_id] = sess
                    await self.write(struct.pack('=IIBB', 1, stream_id,
                                                MSG_CONNECT_RESPONSE, 0))
                else:
                    if payload == SERVICE_NAME:
                        log.info('Rejected connect (paused) stream %d', stream_id)
                    await self.write(struct.pack('=IIBB', 1, stream_id,
                                                MSG_CONNECT_RESPONSE, 3))

            elif ptype == MSG_DATA:
                if stream_id in self.ctl_streams:
                    await self._handle_ctl(stream_id, payload)
                else:
                    sess = self.sessions.get(stream_id)
                    if sess:
                        opcode = payload[0] if payload else -1
                        log.debug('[%d] MSG_DATA opcode=%d len=%d',
                                  stream_id, opcode, len(payload))
                        asyncio.ensure_future(sess.dispatch(payload))
                    else:
                        log.warning('MSG_DATA for unknown stream %d', stream_id)

            elif ptype in (MSG_EOS, MSG_RESET):
                if stream_id in self.ctl_streams:
                    self.ctl_streams.discard(stream_id)
                else:
                    sess = self.sessions.pop(stream_id, None)
                    if sess:
                        log.info('Amiga task disconnected (stream %d, ptype=%d)',
                                 stream_id, ptype)
                        sess.close_all()
                        if ptype == MSG_EOS:
                            frame = struct.pack('=IIB', 0, stream_id, MSG_EOS)
                            await self.write(frame)

# ---- entry point -----------------------------------------------------------

async def main():
    # Support on-demand launch by a314d (-ondemand <fd>)
    try:
        idx = sys.argv.index('-ondemand')
        fd  = int(sys.argv[idx + 1])
        sock = socket.socket(fileno=fd)
        sock.setblocking(False)
        reader, writer = await asyncio.open_connection(sock=sock)
        log.info('bsdsocket started (on-demand, fd=%d)', fd)
        svc = A314BsdService(reader, writer)
        await svc.run(register='ondemand')
    except ValueError:
        reader, writer = await asyncio.open_connection(A314D_HOST, A314D_PORT)
        svc = A314BsdService(reader, writer)
        await svc.run(register=True)

if __name__ == '__main__':
    asyncio.run(main())
