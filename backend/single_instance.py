"""
Single-instance guard (V3.1) — HIGH-PRIORITY safety: never let two SharkNet
network engines run at once (two ARP spoofers on one LAN is dangerous).

Mechanism (no pywin32 dependency): bind a TCP socket to a fixed loopback port.
  * bind succeeds  -> we are the FIRST instance; hold the socket for our lifetime
                      and listen. When a later instance connects and sends the
                      activation token, invoke on_activate() (restore the UI).
  * bind fails     -> another instance already owns it; connect + send the token
                      (asking it to restore its window), then the caller exits.

Loopback-only, so nothing outside the machine can reach it. This module contains
NO network-policy logic; it only guards process uniqueness + relays a "show" ping.
"""
from __future__ import annotations

import logging
import socket
import threading

log = logging.getLogger("sharknet.engine")

GUARD_PORT = 8733          # distinct from the API port (8734+); loopback only
_TOKEN = b"SHARKNET_SHOW\n"


class SingleInstance:
    def __init__(self, port: int = GUARD_PORT):
        self._port = port
        self._sock: socket.socket | None = None
        self._on_activate = None
        self._listener: threading.Thread | None = None
        self._stop = threading.Event()

    def acquire(self) -> bool:
        """True if we are the first instance (we now own the guard). False if
        another instance already holds it."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # no SO_REUSEADDR: we WANT the second bind to fail while the first lives
            s.bind(("127.0.0.1", self._port))
            s.listen(4)
            self._sock = s
            return True
        except OSError:
            s.close()
            return False

    def signal_existing(self) -> bool:
        """Tell the already-running instance to restore its UI. Best-effort."""
        try:
            with socket.create_connection(("127.0.0.1", self._port), timeout=2.0) as c:
                c.sendall(_TOKEN)
            return True
        except OSError as e:
            log.warning("could not signal existing instance: %s", e)
            return False

    def start_listener(self, on_activate) -> None:
        """Begin accepting activation pings (first instance only). `on_activate`
        is called (on the listener thread) whenever another launch pings us."""
        if not self._sock:
            return
        self._on_activate = on_activate
        self._stop.clear()
        self._listener = threading.Thread(target=self._accept_loop,
                                          name="instance-guard", daemon=True)
        self._listener.start()

    def _accept_loop(self) -> None:
        s = self._sock
        if not s:
            return
        s.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _ = s.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                data = conn.recv(64)
                if _TOKEN.strip() in data and self._on_activate:
                    try:
                        self._on_activate()
                    except Exception as e:
                        log.warning("on_activate failed: %s", e)
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    def release(self) -> None:
        """Idempotent: stop listening and free the guard socket (part of shutdown)."""
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
