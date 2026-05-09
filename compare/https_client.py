"""HTTPS server-only client (no client cert) — for protocol comparison."""
import argparse
import logging
import os
import socket
import ssl
from pathlib import Path

log = logging.getLogger("compare.https")


def make_context(ca: Path) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca))
    # NOTE: client is anonymous — no client certificate is loaded
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
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
    parser.add_argument("--server-name", default="localhost")
    parser.add_argument("--ca", type=Path, default=Path("pki/rootCA.pem"))
    parser.add_argument("--message", default="hello over HTTPS")
    args = parser.parse_args()

    logging.basicConfig(level="INFO",
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")

    ctx = make_context(args.ca)

    body = args.message.encode()
    request = (b"POST /msg HTTP/1.1\r\n"
               b"Host: " + args.host.encode() + b"\r\n"
               b"Content-Type: text/plain\r\n"
               b"Content-Length: " + str(len(body)).encode() + b"\r\n"
               b"\r\n" + body)

    with socket.create_connection((args.host, args.port)) as sock:
        with ctx.wrap_socket(sock, server_hostname=args.server_name) as ssock:
            log.info("tls=%s cipher=%s", ssock.version(), ssock.cipher())
            ssock.sendall(request)
            response = ssock.recv(4096)
            log.info("response (%d bytes):\n%s",
                     len(response), response.decode(errors="replace"))


if __name__ == "__main__":
    main()
