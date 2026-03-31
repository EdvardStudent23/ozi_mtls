import socket
import ssl

HOST = "127.0.0.1"
PORT = 8443

# сертифікат і ключ клієнта та ca_cert поки лише теоретично
CLIENT_CERT = "client.pem"
CLIENT_KEY = "client.key"
CA_CERT = "rootCA.pem"

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)

context.check_hostname = False
context.minimum_version = ssl.TLSVersion.TLSv1_2

with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=HOST) as ssock:
        print(" Connected with TLS")
        print("Cipher:", ssock.cipher())
        print("Server cert:", ssock.getpeercert())

        ssock.sendall(b"hello from mtls client")
        data = ssock.recv(4096)
        print(" Response:", data.decode(errors="replace"))
