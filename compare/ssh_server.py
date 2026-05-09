"""SSH server using paramiko — for protocol comparison demo.

Accepts publickey auth from clients whose pubkey is in pki/ssh_authorized_keys.
Replies with a single line "ACK over SSH" via exec_command channel.
"""
import argparse
import base64
import logging
import socket
import threading
from pathlib import Path

import paramiko  # type: ignore[import-untyped]
from paramiko.common import (  # type: ignore[import-untyped]
    AUTH_FAILED,
    AUTH_SUCCESSFUL,
    OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED,
    OPEN_SUCCEEDED,
)

log = logging.getLogger("compare.ssh")


class Server(paramiko.ServerInterface):
    def __init__(self, authorized_key: paramiko.PKey) -> None:
        self._authorized = authorized_key
        self.event = threading.Event()

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        if key == self._authorized:
            log.info("auth ok: user=%s key=%s", username, key.get_fingerprint().hex())
            return AUTH_SUCCESSFUL
        log.warning("auth fail: user=%s key=%s", username, key.get_fingerprint().hex())
        return AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "publickey"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return OPEN_SUCCEEDED
        return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command: bytes) -> bool:
        log.info("exec request: %r", command)
        self.event.set()
        return True


def handle_connection(client_sock: socket.socket, addr,
                      host_key: paramiko.PKey,
                      authorized_key: paramiko.PKey) -> None:
    transport = paramiko.Transport(client_sock)
    transport.add_server_key(host_key)
    server = Server(authorized_key)
    try:
        transport.start_server(server=server)
        chan = transport.accept(timeout=10)
        if chan is None:
            log.warning("no channel from %s", addr)
            return
        if not server.event.wait(timeout=5):
            log.warning("no exec from %s", addr)
            return
        chan.send(b"ACK over SSH\n")
        chan.send_exit_status(0)
        chan.close()
    finally:
        transport.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--host-key", type=Path,
                        default=Path("pki/ssh_host_ed25519_key"))
    parser.add_argument("--authorized-keys", type=Path,
                        default=Path("pki/ssh_authorized_keys"))
    args = parser.parse_args()

    logging.basicConfig(level="INFO",
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")

    host_key = paramiko.Ed25519Key.from_private_key_file(str(args.host_key))

    auth_line = args.authorized_keys.read_text().strip().split()
    # auth_line format: "ssh-ed25519 <base64> <comment>"
    authorized_key = paramiko.Ed25519Key(data=base64.b64decode(auth_line[1]))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((args.host, args.port))
        sock.listen(5)
        log.info("SSH listening on %s:%d", args.host, args.port)

        while True:
            client_sock, addr = sock.accept()
            try:
                handle_connection(client_sock, addr, host_key, authorized_key)
            except Exception as e:
                log.warning("session error from %s: %s", addr, e)
            finally:
                client_sock.close()


if __name__ == "__main__":
    main()
