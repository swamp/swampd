#!/usr/bin/env python3
import argparse
import socket
import sys
import textwrap
import re
import struct

def parse_args():
    p = argparse.ArgumentParser(
        description=textwrap.dedent("""\
            Send a framed UDP datagram with a frag‑datagram header.
            Header fields are all little‑endian.
            """),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    # header fields
    p.add_argument('--version',          type=int, default=1,                     help='Protocol version (u8)')
    p.add_argument('--flags',            type=lambda x: int(x,0), default=0,      help='Flags bitmask (u8)')
    p.add_argument('--connection-id',    type=lambda x: int(x,0), default=0,      help='Connection ID (u16)')
    p.add_argument('--packet-counter',   type=lambda x: int(x,0), default=0,      help='Packet counter (u16)')
    p.add_argument('--msg-id',           type=lambda x: int(x,0), default=0,      help='Message ID (u16)')
    p.add_argument('--frag-index',       type=lambda x: int(x,0), default=0,      help='Fragment index (u16)')
    p.add_argument('--total-frag-count', type=lambda x: int(x,0), default=1,      help='Total fragments (u16)')
    p.add_argument('--sender-ts',        type=lambda x: int(x,0), default=0,      help='Sender timestamp (u32)')
    p.add_argument('--echo-ts',          type=lambda x: int(x,0), default=0,      help='Echo timestamp (u32)')

    # network & payload
    p.add_argument('--host',   default='127.0.0.1',             help='Destination hostname or IP')
    p.add_argument('--port',   type=int, default=50000,        help='Destination UDP port')
    p.add_argument('hexstr',   nargs='?',                      help='Hex string for payload (e.g. "CAFE"). If omitted, prompts.')

    return p.parse_args()

def get_hex_data(hexstr):
    clean = re.sub(r'(?i)0x', '', hexstr)
    clean = re.sub(r'[_\s]', '', clean)
    if len(clean) % 2 != 0:
        sys.exit("ERROR: hex string must have an even number of digits")
    if not all(c in '0123456789abcdefABCDEF' for c in clean):
        sys.exit("ERROR: hex string contains invalid characters")
    try:
        return bytes.fromhex(clean)
    except ValueError as e:
        sys.exit(f"ERROR: invalid hex data ({e})")

def main():
    args = parse_args()

    # Gather header fields into a tuple
    hdr_tuple = (
        args.version & 0xFF,
        args.flags   & 0xFF,
        args.connection_id   & 0xFFFF,
        args.packet_counter  & 0xFFFF,
        args.msg_id          & 0xFFFF,
        args.frag_index      & 0xFFFF,
        args.total_frag_count& 0xFFFF,
        args.sender_ts       & 0xFFFF,
        args.echo_ts         & 0xFFFF,
    )

    # Pack header little‑endian: B B 5×H
    header = struct.pack('<BB7H', *hdr_tuple)

    # Get payload
    if args.hexstr:
        payload = get_hex_data(args.hexstr)
    else:
        try:
            hexstr = input("Enter hex payload (e.g. CAFE): ")
        except EOFError:
            sys.exit("No payload provided, exiting.")
        payload = get_hex_data(hexstr)

    packet = header + payload
    print("  " + packet.hex())

    # Send
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sent = sock.sendto(packet, (args.host, args.port))
    except Exception as e:
        sys.exit(f"UDP send error: {e}")
    finally:
        sock.close()

    print(f"Sent {sent} bytes ({len(header)}‑byte header + {len(payload)}‑byte payload) to {args.host}:{args.port}")

if __name__ == '__main__':
    main()
