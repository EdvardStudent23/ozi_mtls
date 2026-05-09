"""mTLS client: connect to server, present our client cert, exchange one message."""
import argparse
import logging
import os
import socket
import ssl
import sys
from pathlib import Path

log = logging.getLogger("mtls.client")


def make_context(cert: Path | None, key: Path | None, ca: Path, tls_version: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca))
    if cert and key:
        ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))

    ctx.check_hostname = True
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--server-name", default="localhost",
                        help="hostname to verify against server cert SAN")
    parser.add_argument("--cert", type=Path, default=Path("pki/client.pem"))
    parser.add_argument("--key", type=Path, default=Path("pki/client.key"))
    parser.add_argument("--ca", type=Path, default=Path("pki/rootCA.pem"))
    parser.add_argument("--tls", choices=["1.2", "1.3"], default="1.3")
    parser.add_argument("--no-client-cert", action="store_true",
                        help="omit client certificate (for negative scenario)")
    parser.add_argument("--message", default="hello from mtls client")
    parser.add_argument("--log", default="INFO")
    args = parser.parse_args()

    logging.basicConfig(level=args.log,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")

    cert = None if args.no_client_cert else args.cert
    key = None if args.no_client_cert else args.key
    ctx = make_context(cert, key, args.ca, args.tls)

    with socket.create_connection((args.host, args.port)) as sock:
        with ctx.wrap_socket(sock, server_hostname=args.server_name) as ssock:
            log.info("tls=%s cipher=%s", ssock.version(), ssock.cipher())
            server_cert: dict = ssock.getpeercert() or {}  # type: ignore[assignment]
            subj = dict(rdn[0] for rdn in server_cert.get("subject", ()))
            log.info("server cert CN=%s notAfter=%s",
                     subj.get("commonName"), server_cert.get("notAfter"))

            ssock.sendall(args.message.encode())
            data = ssock.recv(4096)
            log.info("response: %r", data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
