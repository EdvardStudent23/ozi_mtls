# client_secure.py
import socket, ssl

HOST        = "127.0.0.1"
PORT        = 8443
CLIENT_CERT = "../../client.pem"
CLIENT_KEY  = "../../client.key"
CA_CERT     = "../../rootCA.pem"

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
context.check_hostname  = False
context.minimum_version = ssl.TLSVersion.TLSv1_2  #def from downgrade. i set the min version 1.2

print("[SECURE CLIENT] Connecting with minimum TLS 1.2...")

try:
    with socket.create_connection((HOST, PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=HOST) as ssock:
            print(f"  TLS Version : {ssock.version()}")
            print(f"  Cipher   : {ssock.cipher()[0]}")
            ssock.sendall(b"hello via secure TLS 1.2-1.3S")
            data = ssock.recv(4096)
            print(f" Response: {data.decode()}")
except ssl.SSLError as e:
    print(f" Blocked: {e}")
    print("  Downgrade attack prevented!")
