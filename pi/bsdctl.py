#!/usr/bin/env python3
"""
bsdctl.py - a314bsd control service ("bsdctl" A314 service)

Backs the `bsdnet` CLI tool and the network on/off GUI (bsdnetgui).  Lets the
Amiga pause / resume the bsdsocket proxy — and now also query net status and
ping a host — without touching bsdsocket.library.

Wire protocol (matches amiga/bsdnet.c + amiga/bsdnetgui.c):
  Amiga connects to the "bsdctl" A314 service, writes ONE request packet,
  reads ONE response packet, then EOS.

  Request  (Amiga -> Pi):  cmd(1)  [arg bytes ...]
  Response (Pi -> Amiga):  status(1)  textlen(1)  text[textlen]

    cmd:     0x01 QUERY   0x02 PAUSE   0x03 RESUME   0x04 STATUS   0x05 PING
    status:  0x01 RUNNING 0x02 PAUSED  0x03 OK       0x00 ERROR
    text:    optional ASCII (<= 200 bytes); '\n' separates lines.  Empty for
             the simple QUERY/PAUSE/RESUME toggles (the GUI supplies its own
             wording); carries the report for STATUS and PING.

State is a flag FILE shared with bsdsocket.py (separate a314d processes):
    <this dir>/bsdsocket.paused  exists  -> paused (new connections blocked)
                                 absent  -> running
bsdsocket.py checks this file in its CONNECT handler and returns ENETDOWN
while paused, so existing connections keep working but new ones are refused.

Startup modes mirror bsdsocket.py:
  - standalone:  python3 bsdctl.py            (registers 'bsdctl' with a314d)
  - on-demand:   python3 bsdctl.py -ondemand <fd>   (a314d spawns us)
"""

import asyncio
import logging
import os
import re
import socket
import struct
import sys

# --------------------------------------------------------------------------
A314D_HOST   = 'localhost'
A314D_PORT   = 7110
SERVICE_NAME = b'bsdctl'

MSG_REGISTER_REQ     = 1
MSG_REGISTER_RES     = 2
MSG_CONNECT          = 9
MSG_CONNECT_RESPONSE = 10
MSG_DATA             = 11
MSG_EOS              = 12
MSG_RESET            = 13

# Command bytes (Amiga -> Pi)
BSDCTL_QUERY   = 0x01
BSDCTL_PAUSE   = 0x02
BSDCTL_RESUME  = 0x03
BSDCTL_STATUS  = 0x04
BSDCTL_PING    = 0x05
# Status bytes (Pi -> Amiga)
BSDCTL_ERROR   = 0x00
BSDCTL_RUNNING = 0x01
BSDCTL_PAUSED  = 0x02
BSDCTL_OK      = 0x03

MAX_TEXT = 200

# Flag file shared with bsdsocket.py — both scripts live in the same dir
# (/opt/a314), so this resolves to the same path in both.
PAUSE_FLAG = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          'bsdsocket.paused')

# Accept only sane host/IP characters — this becomes an argv to `ping` (never
# a shell string, but reject junk anyway so we don't pass stray flags).
_HOST_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,119})$')

logging.basicConfig(
    format='%(levelname)s %(asctime)s %(name)s:%(lineno)d: %(message)s')
log = logging.getLogger('bsdctl')
log.setLevel(logging.WARNING)


def is_paused():
    return os.path.exists(PAUSE_FLAG)


def set_paused(paused):
    if paused:
        try:
            open(PAUSE_FLAG, 'w').close()
        except OSError as e:
            log.warning('could not create %s: %s', PAUSE_FLAG, e)
    else:
        try:
            os.remove(PAUSE_FLAG)
        except FileNotFoundError:
            pass
        except OSError as e:
            log.warning('could not remove %s: %s', PAUSE_FLAG, e)


def _pi_primary_ip():
    """Pi's outward-facing IP (no packets sent — just picks the route)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 53))
        return s.getsockname()[0]
    except OSError:
        return '?'
    finally:
        s.close()


def _net_status_text():
    state = 'OFFLINE (paused)' if is_paused() else 'ONLINE'
    host  = socket.gethostname()
    ip    = _pi_primary_ip()
    return ('Proxy: %s\nPi: %s\nPi IP: %s' % (state, host, ip)).encode('ascii', 'ignore')


async def _do_ping(arg):
    """arg = host bytes.  Returns (status_byte, text_bytes)."""
    host = arg.decode('ascii', 'ignore').strip()
    if not _HOST_RE.match(host):
        return (BSDCTL_ERROR, b'Enter a valid host or IP')
    try:
        proc = await asyncio.create_subprocess_exec(
            'ping', '-c', '2', '-w', '4', host,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL)
        out, _ = await proc.communicate()
    except OSError as e:
        return (BSDCTL_ERROR, ('ping failed: %s' % e).encode('ascii', 'ignore'))

    text = out.decode('ascii', 'ignore')
    ip = ''
    m = re.search(r'\(([0-9.]+)\)', text)
    if m:
        ip = m.group(1)
    avg = ''
    m = re.search(r'=\s*[\d.]+/([\d.]+)/', text)     # rtt min/avg/max
    if m:
        avg = m.group(1)
    recv = ''
    m = re.search(r'(\d+) received', text)
    if m:
        recv = m.group(1)

    where = host if not ip or ip == host else '%s (%s)' % (host, ip)
    if proc.returncode == 0 and recv not in ('', '0'):
        detail = 'avg %s ms' % avg if avg else 'reachable'
        return (BSDCTL_OK, ('%s\n%s, %s received' % (where, detail, recv)).encode('ascii', 'ignore'))
    return (BSDCTL_ERROR, ('%s\nunreachable (no reply)' % where).encode('ascii', 'ignore'))


async def handle_request(payload):
    """payload = cmd byte + optional args.  Returns (status_byte, text_bytes)."""
    if not payload:
        return (BSDCTL_PAUSED if is_paused() else BSDCTL_RUNNING, b'')
    cmd = payload[0]
    arg = payload[1:]
    if cmd == BSDCTL_PAUSE:
        set_paused(True)
        log.warning('network PAUSED (new connections blocked)')
        return (BSDCTL_PAUSED, b'')
    if cmd == BSDCTL_RESUME:
        set_paused(False)
        log.warning('network RESUMED')
        return (BSDCTL_RUNNING, b'')
    if cmd == BSDCTL_STATUS:
        return (BSDCTL_OK, _net_status_text())
    if cmd == BSDCTL_PING:
        return await _do_ping(arg)
    # QUERY or anything else: report current state
    return (BSDCTL_PAUSED if is_paused() else BSDCTL_RUNNING, b'')


def _pack_response(status, text):
    text = text[:MAX_TEXT]
    return bytes([status & 0xff, len(text) & 0xff]) + text


class BsdCtlService:
    def __init__(self, reader=None, writer=None, do_register=True):
        self.reader = reader
        self.writer = writer
        self.do_register = do_register

    async def run(self):
        if self.reader is None:
            self.reader, self.writer = await asyncio.open_connection(
                A314D_HOST, A314D_PORT)
        if self.do_register:
            await self._register()
            log.warning('bsdctl ready (standalone)')
        else:
            log.warning('bsdctl ready (on-demand)')
        await self._read_loop()

    async def _register(self):
        pkt = struct.pack('=IIB', len(SERVICE_NAME), 0, MSG_REGISTER_REQ) + SERVICE_NAME
        self.writer.write(pkt)
        await self.writer.drain()
        hdr = await self.reader.readexactly(9)
        plen, sid, mtype = struct.unpack('=IIB', hdr)
        if plen:
            await self.reader.readexactly(plen)
        if mtype != MSG_REGISTER_RES:
            raise RuntimeError('bsdctl registration failed: msg=%d' % mtype)

    async def _read_loop(self):
        while True:
            hdr = await self.reader.readexactly(9)
            plen, sid, mtype = struct.unpack('=IIB', hdr)
            payload = await self.reader.readexactly(plen) if plen else b''

            if mtype == MSG_CONNECT:
                # Accept the stream (1-byte status 0 = accept)
                self.writer.write(struct.pack('=IIBB', 1, sid, MSG_CONNECT_RESPONSE, 0))
                await self.writer.drain()

            elif mtype == MSG_DATA:
                # One request packet -> one response packet back.
                if payload:
                    status, text = await handle_request(payload)
                    resp = _pack_response(status, text)
                    self.writer.write(struct.pack('=IIB', len(resp), sid, MSG_DATA) + resp)
                    await self.writer.drain()

            elif mtype == MSG_EOS or mtype == MSG_RESET:
                if mtype == MSG_EOS:
                    self.writer.write(struct.pack('=IIB', 0, sid, MSG_EOS))
                    await self.writer.drain()


async def amain():
    try:
        idx = sys.argv.index('-ondemand')
        fd  = int(sys.argv[idx + 1])
        sock = socket.socket(fileno=fd)
        sock.setblocking(False)
        reader, writer = await asyncio.open_connection(sock=sock)
        await BsdCtlService(reader=reader, writer=writer, do_register=False).run()
    except ValueError:
        await BsdCtlService().run()


def main():
    if '-d' in sys.argv or '--debug' in sys.argv:
        log.setLevel(logging.DEBUG)
    try:
        asyncio.run(amain())
    except (KeyboardInterrupt, asyncio.IncompleteReadError):
        pass


if __name__ == '__main__':
    main()
