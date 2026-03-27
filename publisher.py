#!/usr/bin/env python3
"""
Reliable Group Notification System - Publisher
Project #18

Sends notifications to groups via the C server.
Supports both reliable and best-effort modes.

Usage:
  python3 publisher.py --server 127.0.0.1 --port 9000 --group 1 --msg "Hello group!"
  python3 publisher.py --server 127.0.0.1 --group 1 --msg "Alert!" --mode reliable
  python3 publisher.py --benchmark   # run throughput benchmark
"""

import argparse
import socket
import struct
import threading
import time
import zlib
from dataclasses import dataclass

MAGIC = 0xA5B3
MAX_PAYLOAD = 1024
HEADER_FMT = "!HBBIIHHi"
HEADER_SIZE = struct.calcsize(HEADER_FMT)


def build_packet(ptype, seq, group_id, payload=b"", ack_num=0, flags=0):
    plen = len(payload)
    # zero checksum first
    hdr = struct.pack(HEADER_FMT, MAGIC, ptype, flags, seq, ack_num, group_id, plen, 0)
    data = hdr + payload
    cs = zlib.crc32(data) & 0xFFFFFFFF
    cs_signed = struct.unpack("!i", struct.pack("!I", cs))[0]
    hdr = struct.pack(
        HEADER_FMT, MAGIC, ptype, flags, seq, ack_num, group_id, plen, cs_signed
    )
    return hdr + payload


class Publisher:
    def __init__(self, server_ip, server_port):
        self.server = (server_ip, server_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2.0)
        self.seq = 1
        self.acks = {}
        self.lock = threading.Lock()

    def _next_seq(self):
        with self.lock:
            s = self.seq
            self.seq += 1
            return s

    def notify(self, group_id: int, message: str, reliable: bool = True) -> bool:
        seq = self._next_seq()
        ptype = 0x01 if reliable else 0x07
        flags = 0x01 if reliable else 0x00
        pkt = build_packet(
            ptype, seq, group_id, message.encode()[:MAX_PAYLOAD], flags=flags
        )
        # try up to 3 times
        for attempt in range(3):
            self.sock.sendto(pkt, self.server)
            try:
                data, _ = self.sock.recvfrom(HEADER_SIZE + MAX_PAYLOAD)
                if len(data) < HEADER_SIZE:
                    continue
                fields = struct.unpack(HEADER_FMT, data[:HEADER_SIZE])
                _, rtype, _, _, rack, _, _, _ = fields
                if rtype == 0x02 and rack == seq:
                    return True
            except socket.timeout:
                print(f"  (timeout, retry {attempt + 1}/3...)")
        return False

    def benchmark(self, group_id: int, n: int = 100, reliable: bool = True):
        """Throughput benchmark: send n messages, measure delivery rate."""
        print(f"\n{'─' * 55}")
        print(
            f"BENCHMARK: {n} messages | group={group_id} | mode={'reliable' if reliable else 'best-effort'}"
        )
        print(f"{'─' * 55}")

        t0 = time.monotonic()
        success = 0
        for i in range(n):
            msg = f"benchmark msg #{i + 1:04d} | ts={time.time():.3f}"
            ok = self.notify(group_id, msg, reliable=reliable)
            if ok:
                success += 1
            if (i + 1) % 10 == 0:
                print(
                    f"  Sent {i + 1}/{n}  delivered={success}  "
                    f"rate={100 * success / (i + 1):.1f}%"
                )

        elapsed = time.monotonic() - t0
        print(f"\nResults:")
        print(f"  Total sent   : {n}")
        print(f"  Delivered    : {success}")
        print(f"  Lost         : {n - success}")
        print(f"  Delivery rate: {100 * success / n:.1f}%")
        print(f"  Throughput   : {n / elapsed:.1f} msg/s")
        print(f"  Elapsed      : {elapsed:.2f}s")
        print(f"{'─' * 55}\n")

    def close(self):
        self.sock.close()


def main():
    parser = argparse.ArgumentParser(description="Group Notification Publisher")
    parser.add_argument("--server", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--group", type=int, default=1)
    parser.add_argument("--msg", default=None, help="Message to send")
    parser.add_argument(
        "--mode", choices=["reliable", "best-effort"], default="reliable"
    )
    parser.add_argument("--benchmark", action="store_true")
    parser.add_argument("--count", type=int, default=100, help="Messages for benchmark")
    args = parser.parse_args()

    pub = Publisher(args.server, args.port)

    if args.benchmark:
        pub.benchmark(args.group, args.count, reliable=(args.mode == "reliable"))
        # also run best-effort for comparison
        if args.mode == "reliable":
            pub.benchmark(args.group, args.count, reliable=False)
    elif args.msg:
        reliable = args.mode == "reliable"
        print(
            f"Sending {'reliable' if reliable else 'best-effort'} notification to group {args.group}..."
        )
        ok = pub.notify(args.group, args.msg, reliable=reliable)
        print(
            f"Result: {'✓ ACKed by server — check subscriber dashboard' if ok else '✗ No ACK received'}"
        )
    else:
        parser.print_help()

    pub.close()


if __name__ == "__main__":
    main()
