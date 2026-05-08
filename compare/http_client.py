"""Plain HTTP client — for protocol comparison demo."""
import argparse
import logging
import socket

log = logging.getLogger("compare.http")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--message", default="hello over HTTP")
    args = parser.parse_args()

    logging.basicConfig(level="INFO",
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")

    body = args.message.encode()
    request = (b"POST /msg HTTP/1.1\r\n"
               b"Host: " + args.host.encode() + b"\r\n"
               b"Content-Type: text/plain\r\n"
               b"Content-Length: " + str(len(body)).encode() + b"\r\n"
               b"\r\n" + body)

    with socket.create_connection((args.host, args.port)) as sock:
        sock.sendall(request)
        response = sock.recv(4096)
        log.info("response (%d bytes):\n%s",
                 len(response), response.decode(errors="replace"))


if __name__ == "__main__":
    main()
