"""Plain HTTP echo server — for protocol comparison demo (NO encryption)."""
import argparse
import logging
import socket

log = logging.getLogger("compare.http")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    logging.basicConfig(level="INFO",
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")

    body = b"ACK over HTTP\n"
    response = (b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"\r\n" + body)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((args.host, args.port))
        sock.listen(5)
        log.info("HTTP listening on %s:%d (NO ENCRYPTION)", args.host, args.port)

        while True:
            conn, addr = sock.accept()
            with conn:
                data = conn.recv(4096)
                log.info("from %s received %d bytes:\n%s",
                         addr, len(data), data.decode(errors="replace"))
                conn.sendall(response)


if __name__ == "__main__":
    main()
