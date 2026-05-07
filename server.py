import socket
import ssl
from pathlib import Path

HOST = "0.0.0.0"
PORT = 8443

PKI = Path(__file__).parent / "pki"
SERVER_CERT = str(PKI / "server.pem")
SERVER_KEY = str(PKI / "server.key")
CA_CERT = str(PKI / "rootCA.pem")

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
context.load_verify_locations(cafile=CA_CERT)
context.verify_mode = ssl.CERT_REQUIRED
context.minimum_version = ssl.TLSVersion.TLSv1_2


def _name(rdn_seq):
    return dict(x[0] for x in rdn_seq) if rdn_seq else {}


def handle(raw_conn, addr):
    try:
        conn = context.wrap_socket(raw_conn, server_side=True)
    except ssl.SSLError as e:
        print(f"[!] TLS handshake failed from {addr}: {e}")
        raw_conn.close()
        return

    try:
        cert = conn.getpeercert() or {}
        subj = _name(cert.get("subject"))
        issuer = _name(cert.get("issuer"))
        print(f"[+] connected: {addr}")
        print(f"    client CN: {subj.get('commonName')}")
        print(f"    issuer CN: {issuer.get('commonName')}")
        print(f"    cipher:    {conn.cipher()}")
        data = conn.recv(4096)
        print(f"    payload:   {data.decode(errors='replace')!r}")
        conn.sendall(b"ACK: secure message received")
    except (ssl.SSLError, OSError) as e:
        print(f"[!] connection error from {addr}: {e}")
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.close()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f"[+] mTLS server listening on {HOST}:{PORT}")
        while True:
            raw_conn, addr = sock.accept()
            handle(raw_conn, addr)


if __name__ == "__main__":
    main()
