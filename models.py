# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""Pydantic models for Network Packet Anomaly Detection Environment."""

from pydantic import BaseModel, Field
from typing import Optional


class NetworkPacketAction(BaseModel):
    """Action for the Network Packet Anomaly Detection environment."""
    classification: str = Field(..., description="'normal' or 'anomaly'")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Confidence level 0.0-1.0")
    reason: Optional[str] = Field(default=None, description="Explanation for the classification")

    class Config:
        json_schema_extra = {
            "example": {
                "classification": "anomaly",
                "confidence": 0.95,
                "reason": "Detected SYN flood pattern"
            }
        }


class NetworkPacketObservation(BaseModel):
    """Observation from the Network Packet Anomaly Detection environment."""
    source_ip: str = Field(..., description="Source IP address")
    dest_ip: str = Field(..., description="Destination IP address")
    protocol: str = Field(..., description="Protocol (TCP, UDP, ICMP, etc.)")
    src_port: int = Field(..., ge=0, le=65535, description="Source port")
    dst_port: int = Field(..., ge=0, le=65535, description="Destination port")
    packet_size: int = Field(..., description="Packet size in bytes")
    flags: list = Field(default_factory=list, description="TCP flags")
    payload_entropy: float = Field(..., ge=0.0, le=8.0, description="Shannon entropy of payload")
    inter_arrival_time_ms: float = Field(..., description="Time since last packet in ms")
    attack_type: str = Field(..., description="Ground truth attack type")
    is_anomaly: bool = Field(..., description="Ground truth: True if malicious")
    packet_number: int = Field(..., description="Packet number in stream")
    reward: float = Field(default=0.0, description="Reward for last action")
    done: bool = Field(default=False, description="Episode complete")

    class Config:
        json_schema_extra = {
            "example": {
                "source_ip": "192.168.1.100",
                "dest_ip": "10.0.0.1",
                "protocol": "TCP",
                "src_port": 54321,
                "dst_port": 80,
                "packet_size": 512,
                "flags": ["SYN"],
                "payload_entropy": 6.5,
                "inter_arrival_time_ms": 0.5,
                "attack_type": "normal",
                "is_anomaly": False,
                "packet_number": 1,
                "reward": 0.0,
                "done": False
            }
        }
