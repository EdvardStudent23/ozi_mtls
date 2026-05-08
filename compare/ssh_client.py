"""SSH client using paramiko — for protocol comparison demo."""
import argparse
import logging
from pathlib import Path

import paramiko  # type: ignore[import-untyped]

log = logging.getLogger("compare.ssh")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--user", default="ozi")
    parser.add_argument("--key", type=Path,
                        default=Path("pki/ssh_client_ed25519_key"))
    parser.add_argument("--command", default="hello over SSH")
    args = parser.parse_args()

    logging.basicConfig(level="INFO",
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            args.host,
            port=args.port,
            username=args.user,
            key_filename=str(args.key),
            look_for_keys=False,
            allow_agent=False,
        )
        transport = client.get_transport()
        if transport is None:
            raise RuntimeError("no transport")
        log.info("ssh ok: cipher=%s mac=%s kex=%s",
                 transport.local_cipher,
                 transport.local_mac,
                 transport.get_security_options().kex)
        stdin, stdout, stderr = client.exec_command(args.command)
        data = stdout.read()
        log.info("response: %r", data)
    finally:
        client.close()


if __name__ == "__main__":
    main()
