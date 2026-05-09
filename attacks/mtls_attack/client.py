import socket, ssl

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="rootCA.pem")
context.load_cert_chain("client.pem", "client.key")
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.check_hostname = False 

print("[CLIENT] Connecting to 10.0.0.1:8443 via TLS 1.3")
try:
    with socket.create_connection(('10.0.0.1', 8443)) as sock:
        with context.wrap_socket(sock, server_hostname='10.0.0.1') as ssock:
            print(f"[CLIENT] Protocol: {ssock.version()}")
            ssock.sendall(b"GET /secret_data HTTP/1.1\r\nHost: 10.0.0.1")
            response = ssock.recv(1024)
            print(f"[CLIENT] Response: {response.decode()}")
except Exception as e:
    print(f"[CLIENT] Connection failed: {e}")
