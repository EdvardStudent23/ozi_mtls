"""mTLS server: accept TLS connections that present a client cert signed by our CA."""
import argparse
import logging
import os
import socket
import ssl
import sys
from pathlib import Path

log = logging.getLogger("mtls.server")


def make_context(cert: Path, key: Path, ca: Path, tls_version: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    ctx.load_verify_locations(cafile=str(ca))
    ctx.verify_mode = ssl.CERT_REQUIRED

    if tls_version == "1.3":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2

    keylog = os.environ.get("SSLKEYLOGFILE")
    if keylog:
        ctx.keylog_filename = keylog
        log.info("SSLKEYLOGFILE -> %s", keylog)
    return ctx


def handle_client(ssock: ssl.SSLSocket, addr) -> None:
    cert: dict = ssock.getpeercert() or {}  # type: ignore[assignment]
    subj = dict(rdn[0] for rdn in cert.get("subject", ()))
    issuer = dict(rdn[0] for rdn in cert.get("issuer", ()))
    log.info("client connected: addr=%s subject=%s issuer=%s notAfter=%s",
             addr, subj.get("commonName"), issuer.get("commonName"), cert.get("notAfter"))
    log.info("cipher=%s tls=%s", ssock.cipher(), ssock.version())

    data = ssock.recv(4096)
    log.info("received: %r", data)
    ssock.sendall(b"ACK: secure message received\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", type=Path, default=Path("pki/server.pem"))
    parser.add_argument("--key", type=Path, default=Path("pki/server.key"))
    parser.add_argument("--ca", type=Path, default=Path("pki/rootCA.pem"))
    parser.add_argument("--tls", choices=["1.2", "1.3"], default="1.3")
    parser.add_argument("--log", default="INFO")
    args = parser.parse_args()

    logging.basicConfig(level=args.log,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")

    ctx = make_context(args.cert, args.key, args.ca, args.tls)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((args.host, args.port))
        sock.listen(5)
        log.info("listening on %s:%d (TLS %s)", args.host, args.port, args.tls)

        while True:
            client_sock, addr = sock.accept()
            try:
                ssock = ctx.wrap_socket(client_sock, server_side=True)
                try:
                    handle_client(ssock, addr)
                finally:
                    ssock.close()
            except ssl.SSLError as e:
                log.warning("TLS handshake failed from %s: %s", addr, e)
            except Exception as e:
                log.error("unexpected error from %s: %s", addr, e)
            finally:
                client_sock.close()


if __name__ == "__main__":
    sys.exit(main() or 0)
