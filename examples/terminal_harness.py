import argparse
import signal
import sys
import time

from python_bitchat_client import (
    ChatMessage,
    ClientStatus,
    configure_logging,
    create_client,
)
from python_bitchat_client.keys import IdentityKeyPair


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="python-bitchat-client terminal harness"
    )
    parser.add_argument("--handle", default="python-harness", help="nickname/handle")
    parser.add_argument("--channel", default="#mesh", help="channel name")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="python-bitchat-client logger level",
    )
    return parser


def _print_help() -> None:
    print("Commands:")
    print("  /help   Show this help")
    print("  /peers  Show discovered peers")
    print("  /sessions  Show Noise session states")
    print("  /reset-sessions  Clear all Noise sessions")
    print("  /dm <target> <text>  Send private message")
    print("  /quit   Exit harness")
    print("  /exit   Exit harness")
    print("  <text>  Send text to active channel")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    configure_logging(args.log_level)

    identity = IdentityKeyPair.generate()

    client = create_client(identity=identity)

    running = True

    def on_message(message: ChatMessage) -> None:
        tag = "dm" if message.is_private else message.channel
        print(f"\n[recv][{tag}] <{message.sender}> {message.text}")
        print("> ", end="", flush=True)

    def on_status(status: ClientStatus) -> None:
        print(f"\n[status][{status.level}] {status.code}: {status.detail}")
        print("> ", end="", flush=True)

    def _shutdown(_signum: int, _frame) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    client.set_message_handler(on_message)
    client.set_status_handler(on_status)
    client.set_handle(args.handle)
    client.join_channel(args.channel)
    client.start()

    print("python-bitchat-client terminal harness")
    print(f"handle={args.handle} channel={args.channel}")
    _print_help()

    while running:
        try:
            line = input("> ").strip()
        except EOFError:
            break

        if not line:
            continue
        if line in {"/quit", "/exit"}:
            break
        if line == "/help":
            _print_help()
            continue
        if line == "/peers":
            peers = client.list_peers()
            if not peers:
                print("[peers] none")
            else:
                for peer in peers:
                    print(f"[peer] {peer.nickname} ({peer.peer_id})")
            continue
        if line == "/sessions":
            sessions = client.list_sessions()
            if not sessions:
                print("[sessions] none")
            else:
                for peer_id, state in sorted(sessions.items()):
                    print(f"[session] {peer_id}: {state}")
            continue
        if line == "/reset-sessions":
            client.reset_sessions()
            print("[sessions] reset requested")
            continue
        if line.startswith("/dm "):
            parts = line.split(maxsplit=2)
            if len(parts) < 3:
                print("[dm] usage: /dm <target> <text>")
                continue
            sent = client.send_direct_message(parts[1], parts[2])
            if not sent:
                print("[dm] failed")
            continue

        sent = client.send_message(line)
        if not sent:
            print("[send] failed (not connected or backend unavailable)")

    client.stop()
    time.sleep(0.05)
    print("bye")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
