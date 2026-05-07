import socket
import ssl
from pathlib import Path

HOST = "127.0.0.1"
PORT = 8443

PKI = Path(__file__).parent / "pki"
CLIENT_CERT = str(PKI / "client.pem")
CLIENT_KEY = str(PKI / "client.key")
CA_CERT = str(PKI / "rootCA.pem")

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
context.minimum_version = ssl.TLSVersion.TLSv1_2

with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=HOST) as ssock:
        cert = ssock.getpeercert() or {}
        subj = dict(x[0] for x in cert.get("subject", ()))  # type: ignore[arg-type,misc]
        print("[+] mTLS connected")
        print("    cipher:    ", ssock.cipher())
        print("    server CN: ", subj.get("commonName"))  # type: ignore[arg-type]
        ssock.sendall(b"hello from mtls client")
        data = ssock.recv(4096)
        print("    response:  ", data.decode(errors="replace"))
