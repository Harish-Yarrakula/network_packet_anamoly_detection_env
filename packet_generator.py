# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
Packet Generator for Network Packet Anomaly Detection Environment.

Generates realistic network packets with different attack patterns and benign traffic.
"""

import random
import math
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum


class AttackType(Enum):
    """Types of network attacks."""
    NORMAL = "normal"
    DDoS_SYN_FLOOD = "ddos_syn_flood"
    PORT_SCAN = "port_scan"
    C2_EXFILTRATION = "c2_exfiltration"


@dataclass
class Packet:
    """Represents a single network packet."""
    source_ip: str
    dest_ip: str
    protocol: str
    src_port: int
    dst_port: int
    packet_size: int
    flags: List[str]
    payload_entropy: float
    inter_arrival_time_ms: float
    attack_type: AttackType
    is_anomaly: bool

    def to_features_dict(self) -> Dict[str, Any]:
        """Convert packet to feature dictionary."""
        return {
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "packet_size": self.packet_size,
            "flags": self.flags,
            "payload_entropy": self.payload_entropy,
            "inter_arrival_time_ms": self.inter_arrival_time_ms,
        }


class PacketGenerator:
    """Generates realistic network traffic with different attack patterns."""

    def __init__(self, seed: int = 42):
        """Initialize packet generator."""
        random.seed(seed)
        self.packet_count = 0
        self.normal_src_ips = [
            "192.168.1.100",
            "10.0.0.50",
            "172.16.0.25",
            "192.168.1.200",
        ]
        self.attacker_ips = ["203.0.113.45", "198.51.100.89", "192.0.2.150"]
        self.legitimate_dest_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "208.67.222.222",
            "9.9.9.9",
        ]
        self.legitimate_ports = [80, 443, 53, 25, 587, 22, 3306, 5432]

    def generate_normal_packet(self, src_ip: str = None) -> Packet:
        """Generate a benign/normal packet."""
        if src_ip is None:
            src_ip = random.choice(self.normal_src_ips)

        return Packet(
            source_ip=src_ip,
            dest_ip=random.choice(self.legitimate_dest_ips),
            protocol=random.choice(["TCP", "UDP"]),
            src_port=random.randint(1024, 65535),
            dst_port=random.choice(self.legitimate_ports),
            packet_size=random.randint(64, 1500),
            flags=random.choice([["SYN"], ["ACK"], ["SYN", "ACK"], ["FIN"]]),
            payload_entropy=random.uniform(4.0, 6.5),  # Normal entropy
            inter_arrival_time_ms=random.uniform(10, 100),
            attack_type=AttackType.NORMAL,
            is_anomaly=False,
        )

    def generate_ddos_syn_flood_packet(self, src_ip: str = None, target_ip: str = None) -> Packet:
        """Generate a DDoS SYN flood packet."""
        if src_ip is None:
            src_ip = random.choice(self.attacker_ips)
        if target_ip is None:
            target_ip = "10.0.0.1"  # Target server

        return Packet(
            source_ip=src_ip,
            dest_ip=target_ip,
            protocol="TCP",
            src_port=random.randint(1024, 65535),
            dst_port=80,  # HTTP
            packet_size=40,  # Minimal SYN packet
            flags=["SYN"],
            payload_entropy=0.0,  # No payload
            inter_arrival_time_ms=random.uniform(1, 5),  # Very fast
            attack_type=AttackType.DDoS_SYN_FLOOD,
            is_anomaly=True,
        )

    def generate_port_scan_packet(self, src_ip: str = None, target_ip: str = None) -> Packet:
        """Generate a port scan packet."""
        if src_ip is None:
            src_ip = random.choice(self.attacker_ips)
        if target_ip is None:
            target_ip = "10.0.0.0/24"

        # Sequential port scanning pattern
        ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 5432]
        dst_port = random.choice(ports)

        return Packet(
            source_ip=src_ip,
            dest_ip="10.0.0.1",  # Internal network
            protocol="TCP",
            src_port=random.randint(1024, 65535),
            dst_port=dst_port,
            packet_size=64,  # Standard SYN probe
            flags=["SYN"],
            payload_entropy=0.1,  # Minimal payload
            inter_arrival_time_ms=random.uniform(50, 200),  # Moderate pace
            attack_type=AttackType.PORT_SCAN,
            is_anomaly=True,
        )

    def generate_c2_exfiltration_packet(self, src_ip: str = None) -> Packet:
        """Generate a C2 (Command & Control) exfiltration packet."""
        if src_ip is None:
            src_ip = random.choice(self.normal_src_ips)

        # Looks like encrypted traffic
        return Packet(
            source_ip=src_ip,
            dest_ip=random.choice(["198.51.100.150", "203.0.113.200", "192.0.2.99"]),
            protocol="TCP",
            src_port=random.randint(1024, 65535),
            dst_port=443,  # HTTPS (looks encrypted)
            packet_size=random.randint(512, 1024),  # Medium sized
            flags=["ACK"],
            payload_entropy=random.uniform(7.0, 7.8),  # High entropy (encrypted-like)
            inter_arrival_time_ms=random.uniform(4000, 6000),  # Regular pattern, low volume
            attack_type=AttackType.C2_EXFILTRATION,
            is_anomaly=True,
        )

    def generate_task1_stream(self, num_packets: int = 100) -> List[Packet]:
        """
        Generate Task 1 stream: Easy - DDoS detection.
        Mostly normal + obvious DDoS.
        """
        packets = []
        normal_count = int(num_packets * 0.8)
        ddos_count = num_packets - normal_count

        # Add normal packets
        for _ in range(normal_count):
            packets.append(self.generate_normal_packet())

        # Add obvious DDoS packets (very high rate from same source)
        ddos_src = "203.0.113.45"
        for _ in range(ddos_count):
            packets.append(self.generate_ddos_syn_flood_packet(src_ip=ddos_src))

        random.shuffle(packets)
        return packets

    def generate_task2_stream(self, num_packets: int = 200) -> List[Packet]:
        """
        Generate Task 2 stream: Medium - Multi-attack (DDoS + Port Scan + C2).
        Harder to distinguish between attacks.
        """
        packets = []
        normal_count = int(num_packets * 0.6)
        ddos_count = int(num_packets * 0.15)
        port_scan_count = int(num_packets * 0.15)
        c2_count = num_packets - normal_count - ddos_count - port_scan_count

        # Normal traffic
        for _ in range(normal_count):
            packets.append(self.generate_normal_packet())

        # DDoS (distributed from multiple IPs)
        for i, _ in enumerate(range(ddos_count)):
            src = self.attacker_ips[i % len(self.attacker_ips)]
            packets.append(self.generate_ddos_syn_flood_packet(src_ip=src))

        # Port scans
        for _ in range(port_scan_count):
            packets.append(self.generate_port_scan_packet())

        # C2 exfiltration
        for _ in range(c2_count):
            packets.append(self.generate_c2_exfiltration_packet())

        random.shuffle(packets)
        return packets

    def generate_task3_stream(self, num_packets: int = 300) -> List[Packet]:
        """
        Generate Task 3 stream: Hard - Adversarial/encrypted + low-volume attacks.
        Includes legitimate encrypted traffic + stealthy C2 + polymorphic patterns.
        """
        packets = []

        # Mix of legitimate traffic and attacks
        normal_count = int(num_packets * 0.5)
        encrypted_legit = int(num_packets * 0.2)
        stealthy_c2 = int(num_packets * 0.15)
        fast_ddos = int(num_packets * 0.1)
        leftover = num_packets - normal_count - encrypted_legit - stealthy_c2 - fast_ddos

        # Normal packets
        for _ in range(normal_count):
            packets.append(self.generate_normal_packet())

        # Legitimate encrypted traffic (HTTPS, DNS-over-HTTPS) - high entropy, looks normal
        for _ in range(encrypted_legit):
            packet = self.generate_normal_packet()
            packet.payload_entropy = random.uniform(7.2, 7.9)  # High entropy like real encryption
            packet.flags = ["ACK"]
            packets.append(packet)

        # Stealthy C2: very low volume, regular intervals
        for _ in range(stealthy_c2):
            packets.append(self.generate_c2_exfiltration_packet())

        # Some fast DDoS bursts
        for _ in range(fast_ddos):
            packets.append(self.generate_ddos_syn_flood_packet())

        # Remaining: mixed anomalies
        for _ in range(leftover):
            packets.append(self.generate_port_scan_packet())

        random.shuffle(packets)
        return packets
