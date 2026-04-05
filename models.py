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
    packet_features: dict = Field(default_factory=dict, description="Packet feature dictionary")
    context: dict = Field(default_factory=dict, description="Context information about the packet")
    packet_number: int = Field(..., description="Packet number in stream")
    confidence_so_far: float = Field(default=0.0, description="Confidence calibration so far")
    reward: float = Field(default=0.0, description="Reward for last action")
    done: bool = Field(default=False, description="Episode complete")

    class Config:
        json_schema_extra = {
            "example": {
                "packet_features": {
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
                    "is_anomaly": False
                },
                "context": {
                    "packet_number": 1,
                    "recent_packets_from_src": 2,
                    "recent_packets_to_dst": 1,
                    "is_first_packet_to_dst": True
                },
                "packet_number": 1,
                "confidence_so_far": 0.0,
                "reward": 0.0,
                "done": False
            }
        }
