#!/usr/bin/env python3
"""Forward 127.0.0.1:LISTEN in this network namespace to 127.0.0.1:TARGET inside the
network namespace of process PID. The local-devnet counterpart of `ssh -L` for
r1006_bringup.sh tunnels: a producer's RPC is bound to its own loopback only, so the
orchestrator reaches it through a forwarder, never a public port.

The listening socket is created first, in the caller's namespace; the process then
joins the target namespace (setns), so every outbound connection is made there.
Needs Python 3.12+ (os.setns) and rights over the target namespace (the rehearsal runs
everything inside one user namespace it owns).

  nsfwd.py LISTEN_PORT PID TARGET_PORT
"""

from __future__ import annotations

import os
import socket
import sys
import threading


def pump(a: socket.socket, b: socket.socket) -> None:
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    listen, pid, target = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", listen))
    srv.listen(64)
    fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
    os.setns(fd, os.CLONE_NEWNET)
    os.close(fd)
    while True:
        c, _ = srv.accept()
        try:
            u = socket.create_connection(("127.0.0.1", target), timeout=10)
            u.settimeout(None)
        except OSError:
            c.close()
            continue
        threading.Thread(target=pump, args=(c, u), daemon=True).start()
        threading.Thread(target=pump, args=(u, c), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
