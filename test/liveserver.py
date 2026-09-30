#!/usr/bin/env python3
"""Server end of amiga/bsdlive.c. Run it on the a314 Pi: python3 liveserver.py [port]

  S <n>   read n bytes, check the pattern, answer "OK <n>" or "BAD at <i>"
  R <n>   send n bytes of the pattern
  H       say nothing; hold the connection until the client closes it
"""
import socket
import sys
import threading


def pat(i):
    return ((i * 7 + (i >> 8)) ^ 0x5A) & 0xFF


dump = '-dump' in sys.argv


def handle(c, addr):
    f = c.makefile('rb')
    try:
        if dump:                                # log raw bytes, no protocol
            while True:
                d = c.recv(65536)
                print(addr, 'raw', len(d), repr(d[:60]), flush=True)
                if not d:
                    return
        cmd = f.readline().decode(errors='replace').split()
        print(addr, 'cmd', cmd, flush=True)
        if not cmd:
            return
        if cmd[0] == 'S':
            n = int(cmd[1])
            data = b''
            while len(data) < n:                # chunk by chunk, so a stall shows where
                chunk = f.read1(min(65536, n - len(data)))
                if not chunk:
                    break
                data += chunk
                print(addr, '  got', len(chunk), 'total', len(data), flush=True)
            bad = next((i for i, b in enumerate(data) if b != pat(i)), None)
            if len(data) != n:
                ans = 'SHORT %d' % len(data)
            elif bad is not None:
                ans = 'BAD at %d' % bad
            else:
                ans = 'OK %d' % n
            print(addr, 'S', n, '->', ans, flush=True)
            c.sendall((ans + '\n').encode())
        elif cmd[0] == 'R':
            n = int(cmd[1])
            c.sendall(bytes(pat(i) for i in range(n)))
            print(addr, 'R', n, flush=True)
        elif cmd[0] == 'H':
            print(addr, 'H (holding)', flush=True)
            f.read()
            print(addr, 'H closed by client', flush=True)
    finally:
        c.close()


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('-')]
    port = int(args[0]) if args else 5099
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', port))
    s.listen(5)
    print('listening on 127.0.0.1:%d' % port, flush=True)
    while True:
        c, addr = s.accept()
        threading.Thread(target=handle, args=(c, addr), daemon=True).start()


if __name__ == '__main__':
    main()
