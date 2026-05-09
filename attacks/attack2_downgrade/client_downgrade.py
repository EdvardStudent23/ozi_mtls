# client_downgrade.py
import socket, ssl, os

os.environ['OPENSSL_CONF'] = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '../setup/openssl_legacy.cnf'
)

HOST        = "127.0.0.1"
PORT        = 8443
CLIENT_CERT = "../../client.pem"
CLIENT_KEY  = "../../client.key"
CA_CERT     = "../../rootCA.pem"

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
context.check_hostname  = False
context.maximum_version = ssl.TLSVersion.TLSv1
context.set_ciphers('ALL:@SECLEVEL=0')

print("[DOWNGRADE CLIENT] Connecting with forced TLS 1.0...")

with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=HOST) as ssock:
        version = ssock.version()
        cipher  = ssock.cipher()
        print(f" Connected!")
        print(f" TLS Version : {version}")
        print(f" Cipher  : {cipher[0]}")
        print(f" Key bits : {cipher[2]}")
        if version == "TLSv1":
            print(" DOWNGRADE SUCCESS - using insecure TLS 1.0!")
        ssock.sendall(b"hello via downgraded TLS 1.0")
        data = ssock.recv(4096)
        print(f" Response: {data.decode()}")
