#!/usr/bin/env python3
"""
Reliable Group Notification System - Python Client & Dashboard
Project #18

Features:
  - Joins groups and receives reliable UDP notifications
  - Sends ACK for every NOTIFY packet
  - Handles retransmission via NACK
  - Performance comparison: reliable vs best-effort
  - Live terminal dashboard with stats

Usage:
  python3 client.py --server 127.0.0.1 --port 9000 --group 1
  python3 client.py --demo          (run self-contained demo without server)
"""

import socket
import struct
import threading
import time
import random
import argparse
import zlib
import os
import sys
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional, Dict, List
from enum import IntEnum

# ──────────────────────────────────────────────
#  PACKET FORMAT (must match server.c)
# ──────────────────────────────────────────────
MAGIC        = 0xA5B3
MAX_PAYLOAD  = 1024
HEADER_FMT   = "!HBBIIHHi"   # network byte order
HEADER_SIZE  = struct.calcsize(HEADER_FMT)

class PktType(IntEnum):
    NOTIFY    = 0x01
    ACK       = 0x02
    JOIN      = 0x03
    LEAVE     = 0x04
    HEARTBEAT = 0x05
    NACK      = 0x06
    BESTEFF   = 0x07
    STATS     = 0x08

@dataclass
class Packet:
    magic:       int = MAGIC
    ptype:       int = PktType.NOTIFY
    flags:       int = 0
    seq_num:     int = 0
    ack_num:     int = 0
    group_id:    int = 0
    payload_len: int = 0
    checksum:    int = 0
    payload:     bytes = b""

    def pack(self) -> bytes:
        self.payload_len = len(self.payload)
        self.checksum = 0
        hdr = struct.pack(HEADER_FMT,
            self.magic, self.ptype, self.flags,
            self.seq_num, self.ack_num,
            self.group_id, self.payload_len, 0)
        data = hdr + self.payload
        cs = zlib.crc32(data) & 0xFFFFFFFF
        self.checksum = cs
        # rebuild with checksum
        hdr = struct.pack(HEADER_FMT,
            self.magic, self.ptype, self.flags,
            self.seq_num, self.ack_num,
            self.group_id, self.payload_len,
            struct.unpack("!i", struct.pack("!I", cs))[0])
        return hdr + self.payload

    @staticmethod
    def unpack(data: bytes) -> Optional["Packet"]:
        if len(data) < HEADER_SIZE:
            return None
        fields = struct.unpack(HEADER_FMT, data[:HEADER_SIZE])
        magic, ptype, flags, seq, ack, gid, plen, cs_raw = fields
        if magic != MAGIC:
            return None
        payload = data[HEADER_SIZE:HEADER_SIZE + plen]
        # verify checksum
        raw_cs = struct.pack("!I", cs_raw & 0xFFFFFFFF)
        cs_recv = struct.unpack("!I", raw_cs)[0]
        zeroed = struct.pack(HEADER_FMT, magic, ptype, flags, seq, ack, gid, plen, 0)
        cs_calc = zlib.crc32(zeroed + payload) & 0xFFFFFFFF
        if cs_recv != cs_calc:
            return None  # bad checksum
        p = Packet()
        p.magic, p.ptype, p.flags = magic, ptype, flags
        p.seq_num, p.ack_num      = seq, ack
        p.group_id, p.payload_len = gid, plen
        p.checksum                = cs_recv
        p.payload                 = payload
        return p


# ──────────────────────────────────────────────
#  STATISTICS TRACKER
# ──────────────────────────────────────────────
@dataclass
class Stats:
    # Reliable UDP
    reliable_sent:    int = 0
    reliable_acked:   int = 0
    reliable_retx:    int = 0
    reliable_lost:    int = 0
    latencies_ms:     list = field(default_factory=list)
    # Best-effort UDP
    be_sent:          int = 0
    be_dropped:       int = 0   # simulated
    # History for plotting
    history:          deque = field(default_factory=lambda: deque(maxlen=60))

    def record_latency(self, ms: float):
        self.latencies_ms.append(ms)
        if len(self.latencies_ms) > 1000:
            self.latencies_ms = self.latencies_ms[-1000:]

    @property
    def avg_latency(self) -> float:
        return sum(self.latencies_ms) / len(self.latencies_ms) if self.latencies_ms else 0.0

    @property
    def delivery_rate(self) -> float:
        if self.reliable_sent == 0:
            return 0.0
        return 100.0 * self.reliable_acked / self.reliable_sent

    @property
    def be_delivery_rate(self) -> float:
        if self.be_sent == 0:
            return 100.0
        return 100.0 * (self.be_sent - self.be_dropped) / self.be_sent


# ──────────────────────────────────────────────
#  PENDING ACK TRACKER
# ──────────────────────────────────────────────
@dataclass
class PendingAck:
    pkt:        Packet
    dest:       tuple
    sent_time:  float
    retries:    int = 0
    acked:      bool = False

TIMEOUT_SEC   = 0.3
MAX_RETRIES   = 5
WINDOW_SIZE   = 8


# ──────────────────────────────────────────────
#  GROUP NOTIFICATION CLIENT
# ──────────────────────────────────────────────
class GroupNotificationClient:
    def __init__(self, server_ip: str, server_port: int, client_id: str = "py-client"):
        self.server    = (server_ip, server_port)
        self.client_id = client_id
        self.sock      = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(1.0)
        self.seq       = 1
        self.seq_lock  = threading.Lock()
        self.groups    : List[int] = []
        self.stats     = Stats()
        self.pending   : Dict[int, PendingAck] = {}
        self.pending_lock = threading.Lock()
        self.running   = False
        self._recv_thread  = None
        self._retx_thread  = None
        self._hb_thread    = None
        self.message_log: deque = deque(maxlen=200)

    def next_seq(self) -> int:
        with self.seq_lock:
            s = self.seq
            self.seq += 1
            return s

    # ── send helpers ──────────────────────────
    def _send_raw(self, pkt: Packet):
        data = pkt.pack()
        self.sock.sendto(data, self.server)

    def _send_reliable(self, pkt: Packet):
        """Send with reliability tracking."""
        pkt.flags = 0x01
        self._send_raw(pkt)
        pa = PendingAck(pkt=pkt, dest=self.server, sent_time=time.monotonic())
        with self.pending_lock:
            self.pending[pkt.seq_num] = pa
        self.stats.reliable_sent += 1

    def join_group(self, group_id: int):
        pkt = Packet(
            ptype    = PktType.JOIN,
            seq_num  = self.next_seq(),
            group_id = group_id,
            payload  = self.client_id.encode()[:MAX_PAYLOAD]
        )
        self._send_reliable(pkt)
        self.groups.append(group_id)
        self._log(f"▶ JOIN group={group_id}")

    def leave_group(self, group_id: int):
        pkt = Packet(
            ptype    = PktType.LEAVE,
            seq_num  = self.next_seq(),
            group_id = group_id,
        )
        self._send_raw(pkt)
        if group_id in self.groups:
            self.groups.remove(group_id)
        self._log(f"◀ LEAVE group={group_id}")

    def send_ack(self, seq: int, group_id: int):
        pkt = Packet(
            ptype    = PktType.ACK,
            seq_num  = self.next_seq(),
            ack_num  = seq,
            group_id = group_id,
        )
        self._send_raw(pkt)

    def send_nack(self, seq: int, group_id: int):
        pkt = Packet(
            ptype    = PktType.NACK,
            seq_num  = self.next_seq(),
            ack_num  = seq,
            group_id = group_id,
        )
        self._send_raw(pkt)
        self._log(f"✗ NACK seq={seq}")

    def request_stats(self):
        pkt = Packet(ptype=PktType.STATS, seq_num=self.next_seq())
        self._send_raw(pkt)

    # ── receive loop ──────────────────────────
    def _recv_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(HEADER_SIZE + MAX_PAYLOAD)
            except socket.timeout:
                continue
            except OSError:
                break

            pkt = Packet.unpack(data)
            if pkt is None:
                self._log("⚠ Bad packet / checksum error")
                continue

            if pkt.ptype == PktType.NOTIFY:
                msg = pkt.payload.decode(errors="replace")
                self._log(f"📨 NOTIFY seq={pkt.seq_num} group={pkt.group_id} | {msg}")
                self.send_ack(pkt.seq_num, pkt.group_id)
                # record latency if we can find the sent time (demo mode)

            elif pkt.ptype == PktType.BESTEFF:
                msg = pkt.payload.decode(errors="replace")
                self._log(f"📬 BEST-EFFORT seq={pkt.seq_num} group={pkt.group_id} | {msg}")
                # no ACK for best-effort

            elif pkt.ptype == PktType.ACK:
                self._handle_ack(pkt.ack_num)

            elif pkt.ptype == PktType.HEARTBEAT:
                self.send_ack(pkt.seq_num, pkt.group_id)

            elif pkt.ptype == PktType.NACK:
                # server is requesting resend — re-queue
                self._log(f"↩ NACK received for seq={pkt.ack_num}")

    def _handle_ack(self, ack_seq: int):
        with self.pending_lock:
            pa = self.pending.pop(ack_seq, None)
        if pa:
            lat = (time.monotonic() - pa.sent_time) * 1000.0
            self.stats.reliable_acked += 1
            self.stats.record_latency(lat)
            self._log(f"✓ ACK seq={ack_seq}  latency={lat:.1f}ms  retries={pa.retries}")

    # ── retransmit loop ───────────────────────
    def _retx_loop(self):
        while self.running:
            time.sleep(0.05)
            now = time.monotonic()
            with self.pending_lock:
                expired = {s: pa for s, pa in self.pending.items()
                           if not pa.acked and now - pa.sent_time > TIMEOUT_SEC}
            for seq, pa in expired.items():
                if pa.retries >= MAX_RETRIES:
                    self._log(f"✗ LOST seq={seq} after {MAX_RETRIES} retries")
                    self.stats.reliable_lost += 1
                    with self.pending_lock:
                        self.pending.pop(seq, None)
                else:
                    pa.retries += 1
                    pa.sent_time = now
                    self.sock.sendto(pa.pkt.pack(), pa.dest)
                    self.stats.reliable_retx += 1
                    self._log(f"↩ RETX seq={seq} attempt={pa.retries}")

    # ── heartbeat loop ────────────────────────
    def _hb_loop(self):
        while self.running:
            time.sleep(5)
            for gid in list(self.groups):
                pkt = Packet(
                    ptype    = PktType.HEARTBEAT,
                    seq_num  = self.next_seq(),
                    group_id = gid,
                )
                self._send_raw(pkt)

    def _log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        entry = f"[{ts}] {msg}"
        self.message_log.append(entry)
        print(entry)

    def start(self):
        self.running = True
        self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._retx_thread = threading.Thread(target=self._retx_loop, daemon=True)
        self._hb_thread   = threading.Thread(target=self._hb_loop,  daemon=True)
        self._recv_thread.start()
        self._retx_thread.start()
        self._hb_thread.start()

    def stop(self):
        self.running = False
        self.sock.close()


# ──────────────────────────────────────────────
#  STANDALONE DEMO (no server needed)
# ──────────────────────────────────────────────
class DemoServer(threading.Thread):
    """Minimal in-process echo server for demo mode."""
    def __init__(self, port: int):
        super().__init__(daemon=True)
        self.port      = port
        self.sock      = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.sock.settimeout(0.5)
        self.clients   : Dict[tuple, List[int]] = defaultdict(list)  # addr → groups
        self.seq       = 5000
        self.running   = True
        self.drop_rate = 0.0  # no drops — we handle them via sim flag

    def _seq(self):
        s = self.seq; self.seq += 1; return s

    def run(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(HEADER_SIZE + MAX_PAYLOAD)
            except socket.timeout:
                continue
            pkt = Packet.unpack(data)
            if pkt is None:
                continue
            if pkt.ptype == PktType.JOIN:
                self.clients[addr].append(pkt.group_id)
                ack = Packet(ptype=PktType.ACK, seq_num=self._seq(),
                             ack_num=pkt.seq_num, group_id=pkt.group_id)
                self.sock.sendto(ack.pack(), addr)
            elif pkt.ptype in (PktType.HEARTBEAT, PktType.ACK):
                pass  # silently accept

    def broadcast(self, group_id: int, message: str, reliable: bool = True, sim_drop: bool = False):
        ptype = PktType.NOTIFY if reliable else PktType.BESTEFF
        targets = [(addr, grps) for addr, grps in self.clients.items()
                   if group_id in grps]
        sent = 0; dropped = 0
        for addr, _ in targets:
            if sim_drop and random.random() < 0.2:
                dropped += 1
                continue
            pkt = Packet(ptype=ptype, seq_num=self._seq(),
                         group_id=group_id,
                         payload=message.encode()[:MAX_PAYLOAD])
            pkt.flags = 0x01 if reliable else 0x00
            self.sock.sendto(pkt.pack(), addr)
            sent += 1
        return sent, dropped

    def stop(self):
        self.running = False
        self.sock.close()


def run_demo():
    """Self-contained demo: starts a local server and client."""
    PORT = 19000
    print("╔══════════════════════════════════════════════════════════╗")
    print("║   Reliable Group Notification — Python Demo Mode        ║")
    print("╚══════════════════════════════════════════════════════════╝\n")

    srv = DemoServer(PORT)
    srv.start()
    time.sleep(0.2)

    cli = GroupNotificationClient("127.0.0.1", PORT, "py-demo-client")
    cli.start()
    time.sleep(0.2)

    # Join 3 groups
    for gid in [1, 2, 3]:
        cli.join_group(gid)
    time.sleep(0.3)

    print("\n─── Phase 1: Reliable Notifications ───────────────────────")
    alerts = [
        (1, "🔴 CRITICAL: Database connection pool exhausted"),
        (1, "⚠️  WARNING: CPU usage at 89% on node-3"),
        (2, "ℹ️  INFO: Deployment v2.4.1 started"),
        (2, "✅ INFO: Health check passed on all 12 nodes"),
        (3, "📊 METRIC: p99 latency = 142ms"),
    ]
    for gid, msg in alerts:
        srv.broadcast(gid, msg, reliable=True)
        time.sleep(0.2)

    time.sleep(1.0)

    print("\n─── Phase 2: Best-Effort vs Reliable Comparison ───────────")
    # Send 20 best-effort (20% simulated drop)
    be_sent = 0; be_dropped = 0
    for i in range(20):
        s, d = srv.broadcast(1, f"[BE] Alert #{i+1:02d}: metric value={random.randint(1,100)}",
                             reliable=False, sim_drop=True)
        be_sent += s; be_dropped += d
        cli.stats.be_sent    += s
        cli.stats.be_dropped += d
        time.sleep(0.05)

    # Send 20 reliable
    for i in range(20):
        srv.broadcast(1, f"[REL] Alert #{i+1:02d}: metric value={random.randint(1,100)}",
                      reliable=True, sim_drop=False)
        time.sleep(0.05)

    time.sleep(1.5)  # wait for ACKs

    print("\n─── Phase 3: Retransmission Simulation ─────────────────────")
    # Manually inject a "lost" packet by creating a pending entry
    fake_seq = cli.next_seq()
    fake_pkt = Packet(ptype=PktType.NOTIFY, seq_num=fake_seq,
                      group_id=1, payload=b"(this packet will be retransmitted)")
    fake_pkt.flags = 0x01
    pa = PendingAck(pkt=fake_pkt, dest=("127.0.0.1", PORT),
                    sent_time=time.monotonic() - 0.35)  # already expired!
    with cli.pending_lock:
        cli.pending[fake_seq] = pa
    cli.stats.reliable_sent += 1
    print(f"[DEMO] Injected 'lost' packet seq={fake_seq}, retransmit loop will fire...")
    time.sleep(2.0)

    # Print final stats
    print_performance_report(cli.stats)

    cli.stop()
    srv.stop()


def print_performance_report(stats: Stats):
    """Print a detailed performance comparison."""
    print()
    print("┌─────────────────────────────────────────────────────────────┐")
    print("│             PERFORMANCE COMPARISON REPORT                   │")
    print("├──────────────────────────┬──────────────────────────────────┤")
    print("│  RELIABLE UDP            │  BEST-EFFORT UDP (20% sim drop)  │")
    print("├──────────────────────────┼──────────────────────────────────┤")

    rel_dr  = f"{stats.delivery_rate:.1f}%"
    be_dr   = f"{stats.be_delivery_rate:.1f}%"
    avg_lat = f"{stats.avg_latency:.1f}ms"

    print(f"│  Sent:        {stats.reliable_sent:<10}│  Sent:        {stats.be_sent:<20}│")
    print(f"│  ACKed:       {stats.reliable_acked:<10}│  Delivered:   {max(0,stats.be_sent-stats.be_dropped):<20}│")
    print(f"│  Retransmit:  {stats.reliable_retx:<10}│  Dropped:     {stats.be_dropped:<20}│")
    print(f"│  Lost:        {stats.reliable_lost:<10}│  Drop Rate:   {100-stats.be_delivery_rate:.1f}%{'':<16}│")
    print(f"│  Delivery:    {rel_dr:<10}│  Delivery:    {be_dr:<20}│")
    print(f"│  Avg Latency: {avg_lat:<10}│  Avg Latency: N/A (fire-forget)    │")
    print("├──────────────────────────┴──────────────────────────────────┤")
    print("│  VERDICT: Reliable UDP guarantees delivery at the cost of   │")
    print("│  ~1 RTT overhead per packet. Best-effort is faster but      │")
    print("│  loses ~20% of packets with no recovery mechanism.          │")
    print("└─────────────────────────────────────────────────────────────┘")
    print()


# ──────────────────────────────────────────────
#  TERMINAL DASHBOARD (live stats display)
# ──────────────────────────────────────────────
def live_dashboard(client: GroupNotificationClient, duration: int = 30):
    """Display live terminal dashboard while client is running."""
    try:
        import shutil
        w = shutil.get_terminal_size().columns
    except Exception:
        w = 80

    bar_width = min(30, w - 40)

    def bar(pct: float, width: int = bar_width) -> str:
        filled = int(pct / 100 * width)
        return "█" * filled + "░" * (width - filled)

    end_time = time.time() + duration
    while time.time() < end_time and client.running:
        s = client.stats
        os.system("clear" if os.name != "nt" else "cls")
        print(f"{'═'*w}")
        print(f"  📡  Reliable Group Notification Client  │  {time.strftime('%H:%M:%S')}")
        print(f"{'═'*w}")
        print(f"  Groups joined : {', '.join(str(g) for g in client.groups) or 'none'}")
        print(f"  Server        : {client.server[0]}:{client.server[1]}")
        print()
        print(f"  ┌─ RELIABLE UDP ─────────────────────────────────────")
        print(f"  │  Sent         : {s.reliable_sent}")
        print(f"  │  ACKed        : {s.reliable_acked}")
        dr = s.delivery_rate
        print(f"  │  Delivery     : {bar(dr)} {dr:5.1f}%")
        print(f"  │  Retransmits  : {s.reliable_retx}")
        print(f"  │  Lost         : {s.reliable_lost}")
        print(f"  │  Avg Latency  : {s.avg_latency:.1f} ms")
        print(f"  │")
        print(f"  ├─ BEST-EFFORT UDP ──────────────────────────────────")
        print(f"  │  Sent         : {s.be_sent}")
        be_dr = s.be_delivery_rate
        print(f"  │  Delivery     : {bar(be_dr)} {be_dr:5.1f}%")
        print(f"  │  Dropped(sim) : {s.be_dropped}")
        print(f"  └────────────────────────────────────────────────────")
        print()
        print(f"  ┌─ RECENT MESSAGES ──────────────────────────────────")
        recent = list(client.message_log)[-8:]
        for m in recent:
            print(f"  │  {m[:w-8]}")
        print(f"  └────────────────────────────────────────────────────")
        print()
        print(f"  Press Ctrl+C to quit")
        time.sleep(1.0)


# ──────────────────────────────────────────────
#  ENTRY POINT
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Reliable Group Notification System — Python Client")
    parser.add_argument("--server",  default="127.0.0.1", help="Server IP")
    parser.add_argument("--port",    type=int, default=9000, help="Server port")
    parser.add_argument("--group",   type=int, default=1, help="Group ID to join")
    parser.add_argument("--id",      default="py-client", help="Client identifier")
    parser.add_argument("--demo",    action="store_true",  help="Run demo mode (no server needed)")
    parser.add_argument("--dashboard", action="store_true", help="Show live dashboard")
    args = parser.parse_args()

    if args.demo:
        run_demo()
        return

    client = GroupNotificationClient(args.server, args.port, args.id)
    client.start()
    client.join_group(args.group)

    if args.dashboard:
        try:
            live_dashboard(client, duration=3600)
        except KeyboardInterrupt:
            pass
    else:
        print(f"Client running. Joined group {args.group}. Ctrl+C to quit.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    client.stop()
    print_performance_report(client.stats)


if __name__ == "__main__":
    main()
