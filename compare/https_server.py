"""HTTPS server-only TLS (no client cert required) — for protocol comparison."""
import argparse
import logging
import os
import socket
import ssl
from pathlib import Path

log = logging.getLogger("compare.https")


def make_context(cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    ctx.verify_mode = ssl.CERT_NONE  # KEY DIFFERENCE vs mTLS
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    keylog = os.environ.get("SSLKEYLOGFILE")
    if keylog:
        ctx.keylog_filename = keylog
    return ctx


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8444)
    parser.add_argument("--cert", type=Path, default=Path("pki/server.pem"))
    parser.add_argument("--key", type=Path, default=Path("pki/server.key"))
    args = parser.parse_args()

    logging.basicConfig(level="INFO",
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")

    ctx = make_context(args.cert, args.key)

    body = b"ACK over HTTPS\n"
    response = (b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"\r\n" + body)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((args.host, args.port))
        sock.listen(5)
        log.info("HTTPS listening on %s:%d (server-only TLS, no client cert)",
                 args.host, args.port)

        while True:
            client_sock, addr = sock.accept()
            try:
                ssock = ctx.wrap_socket(client_sock, server_side=True)
                try:
                    log.info("from %s tls=%s cipher=%s",
                             addr, ssock.version(), ssock.cipher())
                    data = ssock.recv(4096)
                    log.info("received %d bytes (encrypted on wire)", len(data))
                    ssock.sendall(response)
                finally:
                    ssock.close()
            except ssl.SSLError as e:
                log.warning("TLS error from %s: %s", addr, e)
            finally:
                client_sock.close()


if __name__ == "__main__":
    main()
