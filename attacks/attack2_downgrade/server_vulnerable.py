import socket
import ssl
import os

os.environ['OPENSSL_CONF'] = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '../setup/openssl_legacy.cnf'
)

HOST        = "0.0.0.0"
PORT        = 8443
SERVER_CERT = "../../server.pem"
SERVER_KEY  = "../../server.key"
CA_CERT     = "../../rootCA.pem"

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
context.load_verify_locations(cafile=CA_CERT)
context.verify_mode     = ssl.CERT_REQUIRED
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.set_ciphers('ALL:@SECLEVEL=0')

print("[VULNERABLE SERVER] Starting...")
print(f"[VULNERABLE SERVER] Port  : {PORT}")
#print(f"[VULNERABLE SERVER] Min TLS : TLS 1.0 (INSECURE)")
print(f"[VULNERABLE SERVER] Ciphers : ALL (including weak)")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(5)

    with context.wrap_socket(sock, server_side=True) as ssock:
        while True:
            conn, addr = ssock.accept()
            version = conn.version()
            cipher  = conn.cipher()
            print(f"\n Client connected from : {addr}")
            print(f" TLS Version      : {version}")
            print(f" Cipher Suite      : {cipher[0]}")
            print(f" Key bits       : {cipher[2]}")
            if version in ("TLSv1", "TLSv1.1"):
                print(f"  DOWNGRADE DETECTED - {version} is insecure!")
            data = conn.recv(4096)
            print(f" Received: {data.decode(errors='replace')}")
            conn.sendall(b"ACK from vulnerable server")
            conn.close()

