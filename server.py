import socket
import ssl

HOST = "0.0.0.0"
PORT = 8443

# сертифікат і ключ сервера та ca_cert поки лише теоретично
SERVER_CERT = "server.pem"
SERVER_KEY = "server.key"
CA_CERT = "rootCA.pem"

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
context.load_verify_locations(cafile=CA_CERT)
context.verify_mode = ssl.CERT_REQUIRED
context.minimum_version = ssl.TLSVersion.TLSv1_2

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((HOST, PORT))
    sock.listen(5)
    print(f" Listening on {HOST}:{PORT}")

    with context.wrap_socket(sock, server_side=True) as ssock:
        while True:
            conn, addr = ssock.accept()
            print(f" TLS client connected from {addr}")
            client_cert = conn.getpeercert()
            print(" Client certificate:")
            print(client_cert)
            data = conn.recv(4096)
            print(f"Received: {data.decode(errors='replace')}")
            conn.sendall(b"ACK: secure message received")
            conn.close()