# CodeAlpha_Basic-Network-Sniffer
🔬 A Python-based network packet analyzer that captures and displays  live traffic with protocol detection, IP analysis, and session summary.

#!/usr/bin/env python3
"""
Network Packet Analyzer
Captures and analyzes network traffic using scapy (with socket fallback).
"""

import sys
import time
import socket
import struct
import argparse
from datetime import datetime
from collections import defaultdict

# ── Try importing scapy ──────────────────────────────────────────────────────
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw, ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ── ANSI Colors ───────────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    DIM     = "\033[2m"

# ── Protocol helpers ──────────────────────────────────────────────────────────
PROTO_COLORS = {
    "TCP":  C.GREEN,
    "UDP":  C.CYAN,
    "ICMP": C.YELLOW,
    "ARP":  C.MAGENTA,
    "DNS":  C.BLUE,
    "HTTP": C.RED,
    "OTHER": C.WHITE,
}

WELL_KNOWN_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}

def port_label(port):
    svc = WELL_KNOWN_PORTS.get(port, "")
    return f"{port}/{svc}" if svc else str(port)


# ══════════════════════════════════════════════════════════════════════════════
#  SCAPY-based analyzer
# ══════════════════════════════════════════════════════════════════════════════
class ScapyAnalyzer:
    """Packet analyzer built on Scapy."""

    def __init__(self, iface=None, count=0, bpf_filter="", verbose=False, show_payload=False):
        self.iface       = iface
        self.count       = count          # 0 = unlimited
        self.bpf_filter  = bpf_filter
        self.verbose     = verbose
        self.show_payload= show_payload
        self.stats       = defaultdict(int)
        self.packet_no   = 0
        self.start_time  = None

    # ── pretty header ─────────────────────────────────────────────────────────
    def _header(self):
        print(f"\n{C.BOLD}{C.CYAN}{'═'*70}{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}  🔬  Network Packet Analyzer  (Scapy mode){C.RESET}")
        print(f"{C.CYAN}{'═'*70}{C.RESET}")
        iface_str = self.iface or "default"
        filt_str  = f"  filter='{self.bpf_filter}'" if self.bpf_filter else ""
        count_str = f"  count={self.count}" if self.count else "  count=∞"
        print(f"  Interface: {C.YELLOW}{iface_str}{C.RESET}{filt_str}{count_str}\n")

    # ── format one packet ─────────────────────────────────────────────────────
    def _format_packet(self, pkt):
        self.packet_no += 1
        ts   = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        no   = f"{self.packet_no:>5}"
        size = len(pkt)

        # ── Layer detection ───────────────────────────────────────────────────
        proto = "OTHER"
        src = dst = sport = dport = flags = info = ""

        if ARP in pkt:
            proto = "ARP"
            src   = pkt[ARP].psrc
            dst   = pkt[ARP].pdst
            op    = "who-has" if pkt[ARP].op == 1 else "is-at"
            info  = f"ARP {op}  {pkt[ARP].hwsrc}"

        elif IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            ttl = pkt[IP].ttl

            if TCP in pkt:
                proto  = "TCP"
                sport  = port_label(pkt[TCP].sport)
                dport  = port_label(pkt[TCP].dport)
                f_byte = pkt[TCP].flags
                flag_s = str(f_byte)
                flags  = f"[{flag_s}]"
                # Detect HTTP
                if pkt[TCP].sport == 80 or pkt[TCP].dport == 80:
                    proto = "HTTP"
                info = f"{src}:{sport} → {dst}:{dport}  {flags}  seq={pkt[TCP].seq}"

            elif UDP in pkt:
                proto  = "UDP"
                sport  = port_label(pkt[UDP].sport)
                dport  = port_label(pkt[UDP].dport)
                info   = f"{src}:{sport} → {dst}:{dport}"
                # Detect DNS
                if DNS in pkt:
                    proto = "DNS"
                    try:
                        qname = pkt[DNS].qd.qname.decode() if pkt[DNS].qd else ""
                        info += f"  query={qname}"
                    except Exception:
                        pass

            elif ICMP in pkt:
                proto = "ICMP"
                icmp_types = {0:"echo-reply", 3:"dest-unreachable",
                              8:"echo-request", 11:"time-exceeded"}
                t = icmp_types.get(pkt[ICMP].type, str(pkt[ICMP].type))
                info = f"{src} → {dst}  type={t}  ttl={ttl}"

            else:
                info = f"{src} → {dst}"

        # ── Color & print ─────────────────────────────────────────────────────
        color = PROTO_COLORS.get(proto, C.WHITE)
        proto_tag = f"{color}{proto:<6}{C.RESET}"
        size_str  = f"{C.DIM}{size:>5}B{C.RESET}"

        if not info and src:
            info = f"{src} → {dst}"

        print(f"  {C.DIM}{ts}{C.RESET} #{no} {proto_tag} {size_str}  {info}")

        # ── Verbose layer dump ────────────────────────────────────────────────
        if self.verbose:
            if IP in pkt:
                ip = pkt[IP]
                print(f"  {C.DIM}  ├─ IP  ver={ip.version} ihl={ip.ihl} tos={ip.tos} "
                      f"len={ip.len} id={ip.id} ttl={ip.ttl} proto={ip.proto}{C.RESET}")
            if TCP in pkt:
                tcp = pkt[TCP]
                print(f"  {C.DIM}  ├─ TCP sport={tcp.sport} dport={tcp.dport} "
                      f"seq={tcp.seq} ack={tcp.ack} window={tcp.window}{C.RESET}")
            if UDP in pkt:
                udp = pkt[UDP]
                print(f"  {C.DIM}  └─ UDP sport={udp.sport} dport={udp.dport} "
                      f"len={udp.len} chksum={hex(udp.chksum)}{C.RESET}")

        # ── Payload ───────────────────────────────────────────────────────────
        if self.show_payload and Raw in pkt:
            raw = bytes(pkt[Raw])[:128]
            hex_str  = " ".join(f"{b:02x}" for b in raw)
            text_str = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
            print(f"  {C.DIM}  payload hex : {hex_str}{C.RESET}")
            print(f"  {C.DIM}  payload text: {text_str}{C.RESET}")

        # ── Stats ─────────────────────────────────────────────────────────────
        self.stats[proto] += 1

    # ── summary ───────────────────────────────────────────────────────────────
    def _summary(self):
        elapsed = time.time() - self.start_time
        total   = sum(self.stats.values())
        print(f"\n{C.BOLD}{C.CYAN}{'─'*70}{C.RESET}")
        print(f"{C.BOLD}  Summary  —  {total} packets in {elapsed:.1f}s{C.RESET}")
        for proto, cnt in sorted(self.stats.items(), key=lambda x: -x[1]):
            color = PROTO_COLORS.get(proto, C.WHITE)
            bar   = "█" * min(40, int(cnt / max(total, 1) * 40))
            print(f"  {color}{proto:<8}{C.RESET} {cnt:>5}  {C.DIM}{bar}{C.RESET}")
        print(f"{C.CYAN}{'═'*70}{C.RESET}\n")

    # ── run ───────────────────────────────────────────────────────────────────
    def run(self):
        self._header()
        self.start_time = time.time()
        kwargs = dict(prn=self._format_packet, store=False)
        if self.iface:       kwargs["iface"]  = self.iface
        if self.bpf_filter:  kwargs["filter"] = self.bpf_filter
        if self.count:       kwargs["count"]  = self.count
        try:
            sniff(**kwargs)
        except KeyboardInterrupt:
            pass
        finally:
            self._summary()


# ══════════════════════════════════════════════════════════════════════════════
#  Raw-socket fallback (Linux / root only, no Scapy)
# ══════════════════════════════════════════════════════════════════════════════
class RawSocketAnalyzer:
    """Minimal packet analyzer using raw sockets (Linux, requires root)."""

    PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

    def __init__(self, count=0, show_payload=False):
        self.count       = count
        self.show_payload= show_payload
        self.stats       = defaultdict(int)
        self.packet_no   = 0
        self.start_time  = None

    def _header(self):
        print(f"\n{C.BOLD}{C.YELLOW}{'═'*70}{C.RESET}")
        print(f"{C.BOLD}{C.YELLOW}  🔬  Network Packet Analyzer  (raw-socket mode){C.RESET}")
        print(f"{C.YELLOW}{'═'*70}{C.RESET}")
        print(f"  {C.DIM}Tip: install scapy for full protocol support → pip install scapy{C.RESET}\n")

    def _parse_ip(self, data):
        iph = struct.unpack("!BBHHHBBH4s4s", data[:20])
        ver_ihl   = iph[0]
        ihl       = (ver_ihl & 0xF) * 4
        protocol  = iph[6]
        src_ip    = socket.inet_ntoa(iph[8])
        dst_ip    = socket.inet_ntoa(iph[9])
        return ihl, protocol, src_ip, dst_ip

    def _parse_tcp(self, data):
        tcph  = struct.unpack("!HHLLBBHHH", data[:20])
        sport = tcph[0]; dport = tcph[1]
        seq   = tcph[2]; ack   = tcph[3]
        flags = tcph[5]
        flag_str = "".join([
            "F" if flags & 0x01 else "",
            "S" if flags & 0x02 else "",
            "R" if flags & 0x04 else "",
            "P" if flags & 0x08 else "",
            "A" if flags & 0x10 else "",
        ])
        return sport, dport, seq, ack, flag_str

    def _parse_udp(self, data):
        udph = struct.unpack("!HHHH", data[:8])
        return udph[0], udph[1]

    def _parse_icmp(self, data):
        icmph = struct.unpack("!BBH", data[:4])
        return icmph[0], icmph[1]  # type, code

    def _format_packet(self, data):
        self.packet_no += 1
        ts   = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        no   = f"{self.packet_no:>5}"
        size = len(data)

        try:
            ihl, protocol, src_ip, dst_ip = self._parse_ip(data)
        except Exception:
            return

        proto = self.PROTO_MAP.get(protocol, "OTHER")
        color = PROTO_COLORS.get(proto, C.WHITE)
        proto_tag = f"{color}{proto:<6}{C.RESET}"
        size_str  = f"{C.DIM}{size:>5}B{C.RESET}"
        payload   = data[ihl:]
        info      = ""

        try:
            if protocol == 6 and len(payload) >= 20:   # TCP
                sport, dport, seq, ack, flags = self._parse_tcp(payload)
                info = (f"{src_ip}:{port_label(sport)} → "
                        f"{dst_ip}:{port_label(dport)}  [{flags}]  seq={seq}")
                if sport == 80 or dport == 80:
                    proto = "HTTP"
                    color = PROTO_COLORS["HTTP"]
                    proto_tag = f"{color}{proto:<6}{C.RESET}"

            elif protocol == 17 and len(payload) >= 8: # UDP
                sport, dport = self._parse_udp(payload)
                info = (f"{src_ip}:{port_label(sport)} → "
                        f"{dst_ip}:{port_label(dport)}")

            elif protocol == 1 and len(payload) >= 4:  # ICMP
                icmp_type, icmp_code = self._parse_icmp(payload)
                icmp_names = {0:"echo-reply", 8:"echo-request",
                              3:"dest-unreachable", 11:"time-exceeded"}
                t    = icmp_names.get(icmp_type, str(icmp_type))
                info = f"{src_ip} → {dst_ip}  type={t} code={icmp_code}"

            else:
                info = f"{src_ip} → {dst_ip}  proto={protocol}"

        except Exception:
            info = f"{src_ip} → {dst_ip}"

        print(f"  {C.DIM}{ts}{C.RESET} #{no} {proto_tag} {size_str}  {info}")

        if self.show_payload and len(payload) > 0:
            raw = payload[:64]
            hex_str  = " ".join(f"{b:02x}" for b in raw)
            text_str = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
            print(f"  {C.DIM}  hex : {hex_str}{C.RESET}")
            print(f"  {C.DIM}  text: {text_str}{C.RESET}")

        self.stats[proto] += 1

    def _summary(self):
        elapsed = time.time() - self.start_time
        total   = sum(self.stats.values())
        print(f"\n{C.BOLD}{C.YELLOW}{'─'*70}{C.RESET}")
        print(f"{C.BOLD}  Summary  —  {total} packets in {elapsed:.1f}s{C.RESET}")
        for proto, cnt in sorted(self.stats.items(), key=lambda x: -x[1]):
            color = PROTO_COLORS.get(proto, C.WHITE)
            bar   = "█" * min(40, int(cnt / max(total, 1) * 40))
            print(f"  {color}{proto:<8}{C.RESET} {cnt:>5}  {C.DIM}{bar}{C.RESET}")
        print(f"{C.YELLOW}{'═'*70}{C.RESET}\n")

    def run(self):
        self._header()
        self.start_time = time.time()
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                              socket.ntohs(0x0003))
        except PermissionError:
            print(f"{C.RED}  ✖  Root/admin privileges required for raw sockets.{C.RESET}")
            print(f"     Run with: {C.YELLOW}sudo python3 packet_analyzer.py{C.RESET}\n")
            sys.exit(1)
        except AttributeError:
            # AF_PACKET not available (macOS / Windows)
            print(f"{C.RED}  ✖  AF_PACKET sockets are Linux-only.{C.RESET}")
            print(f"     Please install scapy: {C.YELLOW}pip install scapy{C.RESET}\n")
            sys.exit(1)

        captured = 0
        try:
            while True:
                raw, _ = s.recvfrom(65535)
                # Skip Ethernet header (14 bytes) to reach IP layer
                self._format_packet(raw[14:])
                captured += 1
                if self.count and captured >= self.count:
                    break
        except KeyboardInterrupt:
            pass
        finally:
            s.close()
            self._summary()


# ══════════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="Network Packet Analyzer — captures & displays live traffic",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  sudo python3 packet_analyzer.py                   # capture all traffic
  sudo python3 packet_analyzer.py -c 50             # capture 50 packets
  sudo python3 packet_analyzer.py -f "tcp port 80"  # HTTP only (Scapy)
  sudo python3 packet_analyzer.py -i eth0 -v -p     # verbose + payload
  sudo python3 packet_analyzer.py --no-scapy        # force raw-socket mode
        """
    )
    parser.add_argument("-i", "--iface",     default=None,  help="Network interface (Scapy only)")
    parser.add_argument("-c", "--count",     type=int, default=0, help="Stop after N packets (0=∞)")
    parser.add_argument("-f", "--filter",    default="",    help="BPF filter string (Scapy only)")
    parser.add_argument("-v", "--verbose",   action="store_true", help="Show parsed layer fields")
    parser.add_argument("-p", "--payload",   action="store_true", help="Show packet payload bytes")
    parser.add_argument("--no-scapy",        action="store_true", help="Force raw-socket mode")
    args = parser.parse_args()

    if SCAPY_AVAILABLE and not args.no_scapy:
        analyzer = ScapyAnalyzer(
            iface=args.iface,
            count=args.count,
            bpf_filter=args.filter,
            verbose=args.verbose,
            show_payload=args.payload,
        )
    else:
        if not SCAPY_AVAILABLE and not args.no_scapy:
            print(f"{C.DIM}  scapy not found — falling back to raw sockets "
                  f"(install with: pip install scapy){C.RESET}")
        analyzer = RawSocketAnalyzer(
            count=args.count,
            show_payload=args.payload,
        )

    print(f"  {C.DIM}Press Ctrl+C to stop and view summary.{C.RESET}")
    analyzer.run()


if __name__ == "__main__":
    main()
