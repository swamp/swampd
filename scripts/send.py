#!/usr/bin/env python3
import argparse
import socket
import sys
import textwrap
import re

def parse_args():
    p = argparse.ArgumentParser(
        description=textwrap.dedent("""\
            Send raw hex bytes over UDP to swampd.
            """),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--host', default='127.0.0.1', help='Destination hostname or IP')
    p.add_argument('--port', type=int, default=50000, help='Destination UDP port')
    p.add_argument(
        'hexstr',
        nargs='?',
        help='Hex string (e.g. CAFE). If omitted, prompts for input.'
    )
    return p.parse_args()

def get_hex_data(hexstr):
    # Remove '0x' prefixes, underscores, and whitespace
    clean = re.sub(r'(?i)0x', '', hexstr)
    clean = re.sub(r'[_\s]', '', clean)
    if len(clean) % 2 != 0:
        sys.exit("ERROR: hex string must have an even number of digits after cleaning delimiters")
    if not all(c in '0123456789abcdefABCDEF' for c in clean):
        sys.exit("ERROR: hex string contains invalid characters")
    try:
        return bytes.fromhex(clean)
    except ValueError as e:
        sys.exit(f"ERROR: invalid hex data ({e})")

def main():
    args = parse_args()
    if args.hexstr:
        data = get_hex_data(args.hexstr)
    else:
        try:
            hexstr = input("Enter hex bytes (e.g. CAFE): ")
        except EOFError:
            sys.exit("No hex provided, exiting.")
        data = get_hex_data(hexstr)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sent = sock.sendto(data, (args.host, args.port))
    except Exception as e:
        sys.exit(f"UDP send error: {e}")
    finally:
        sock.close()

    print(f"Sent {sent} byte{'s' if sent!=1 else ''} to {args.host}:{args.port}")

if __name__ == '__main__':
    main()
