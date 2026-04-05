# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
Network Packet Anomaly Detection Environment Implementation.

Full OpenEnv-compliant environment for network anomaly classification.
Implements the OpenEnv spec with typed models, step(), reset(), and state() methods.
"""

from uuid import uuid4
from typing import Optional, List, Dict, Any
import random

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import State

try:
    from ..models import NetworkPacketAction, NetworkPacketObservation
    from ..packet_generator import PacketGenerator, Packet
    from ..graders import ClassificationResult
except ImportError:
    from models import NetworkPacketAction, NetworkPacketObservation
    from packet_generator import PacketGenerator, Packet
    from graders import ClassificationResult


class NetworkPacketAnomalyDetectionEnvironment(Environment):
    """
    Network Packet Anomaly Detection Environment.

    An RL environment for training agents to classify network packets as normal or anomalous.
    Implements three progressively harder tasks:
    - Task 1 (Easy): DDoS detection with obvious SYN flood patterns
    - Task 2 (Medium): Multi-attack classification (DDoS + Port Scan + C2 + Normal)
    - Task 3 (Hard): Adversarial encrypted traffic + low-volume attacks

    State space:
    - Packet features: source/dest IP, protocol, ports, packet size, flags, entropy, inter-arrival time
    - Context: recent packet patterns, packet number in stream

    Action space:
    - Classification: "normal" or "anomaly"
    - Confidence: 0.0-1.0 (calibration reward)
    - Reason: explanation string

    Reward:
    - True Positive: +1.0 * confidence (encourages confident correct predictions)
    - True Negative: +0.8 * (1 - confidence) (encourages low confidence on normal)
    - False Positive: -0.5 * confidence (penalizes false alarms)
    - False Negative: -1.0 (worst: missed attack)
    """

    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(self, task: int = 1, max_packets: int = 100):
        """
        Initialize the environment.

        Args:
            task: Task number (1, 2, or 3)
            max_packets: Maximum packets per episode
        """
        self.task = max(1, min(3, task))  # Clamp to [1, 3]
        self.max_packets = max_packets
        self.packet_generator = PacketGenerator(seed=random.randint(0, 9999))

        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._packets: List[Packet] = []
        self._current_packet_index = 0
        self._classifications: List[ClassificationResult] = []
        self._cumulative_reward = 0.0
        self._recent_src_ips: Dict[str, int] = {}
        self._recent_dst_ips: Dict[str, int] = {}

    def reset(self) -> NetworkPacketObservation:
        """
        Reset the environment and generate a new packet stream.

        Returns:
            Initial observation (first packet in stream)
        """
        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._current_packet_index = 0
        self._classifications = []
        self._cumulative_reward = 0.0
        self._recent_src_ips = {}
        self._recent_dst_ips = {}

        # Generate packet stream based on task
        if self.task == 1:
            self._packets = self.packet_generator.generate_task1_stream(self.max_packets)
        elif self.task == 2:
            self._packets = self.packet_generator.generate_task2_stream(self.max_packets)
        else:  # task 3
            self._packets = self.packet_generator.generate_task3_stream(self.max_packets)

        # Return first packet
        return self._get_observation_for_packet(0)

    def step(self, action: NetworkPacketAction) -> NetworkPacketObservation:
        """
        Process agent's classification action and move to next packet.

        Args:
            action: Agent's classification (normal/anomaly) with confidence

        Returns:
            Next packet observation + reward
        """
        self._state.step_count += 1

        # Ground truth for current packet
        current_packet = self._packets[self._current_packet_index]
        ground_truth = "anomaly" if current_packet.is_anomaly else "normal"

        # Compute reward based on classification accuracy + confidence calibration
        is_correct = action.classification == ground_truth
        confidence = max(0.0, min(1.0, action.confidence))  # Clamp confidence [0, 1]

        if is_correct:
            if action.classification == "anomaly":
                # True Positive
                reward = 1.0 * confidence
                is_tp, is_tn, is_fp, is_fn = True, False, False, False
            else:
                # True Negative
                reward = 0.8 * (1.0 - confidence)
                is_tp, is_tn, is_fp, is_fn = False, True, False, False
        else:
            if action.classification == "anomaly":
                # False Positive
                reward = -0.5 * confidence
                is_tp, is_tn, is_fp, is_fn = False, False, True, False
            else:
                # False Negative (worst)
                reward = -1.0
                is_tp, is_tn, is_fp, is_fn = False, False, False, True

        # Clamp reward to [-1, 1]
        reward = max(-1.0, min(1.0, reward))
        self._cumulative_reward += reward

        # Record classification
        self._classifications.append(
            ClassificationResult(
                predicted_label=action.classification,
                predicted_confidence=confidence,
                actual_label=ground_truth,
                is_correct=is_correct,
                is_tp=is_tp,
                is_tn=is_tn,
                is_fp=is_fp,
                is_fn=is_fn,
            )
        )

        # Move to next packet
        self._current_packet_index += 1
        done = self._current_packet_index >= len(self._packets)

        if done:
            # Episode over; prepare final observation
            obs = NetworkPacketObservation(
                packet_features={},
                context={},
                packet_number=self._current_packet_index,
                confidence_so_far=self._cumulative_reward / len(self._classifications),
                done=True,
                reward=reward,
            )
            return obs

        # Get next packet observation
        next_obs = self._get_observation_for_packet(self._current_packet_index)
        next_obs.reward = reward

        return next_obs

    def _get_observation_for_packet(self, packet_idx: int) -> NetworkPacketObservation:
        """
        Get observation for a specific packet index.

        Args:
            packet_idx: Index in packet stream

        Returns:
            NetworkPacketObservation
        """
        if packet_idx >= len(self._packets):
            return NetworkPacketObservation(
                packet_features={},
                context={},
                packet_number=packet_idx,
                done=True,
            )

        packet = self._packets[packet_idx]

        # Update recent IP tracking (sliding window)
        self._recent_src_ips[packet.source_ip] = self._recent_src_ips.get(packet.source_ip, 0) + 1
        self._recent_dst_ips[packet.dest_ip] = self._recent_dst_ips.get(packet.dest_ip, 0) + 1

        # Clean old entries (keep recent)
        if len(self._recent_src_ips) > 100:
            self._recent_src_ips = dict(
                sorted(self._recent_src_ips.items(), key=lambda x: -x[1])[:50]
            )
        if len(self._recent_dst_ips) > 100:
            self._recent_dst_ips = dict(
                sorted(self._recent_dst_ips.items(), key=lambda x: -x[1])[:50]
            )

        recent_from_src = self._recent_src_ips.get(packet.source_ip, 0)
        recent_to_dst = self._recent_dst_ips.get(packet.dest_ip, 0)
        is_first_to_dst = recent_to_dst == 1

        context = {
            "packet_number": packet_idx,
            "recent_packets_from_src": recent_from_src,
            "recent_packets_to_dst": recent_to_dst,
            "is_first_packet_to_dst": is_first_to_dst,
        }

        return NetworkPacketObservation(
            packet_features=packet.to_features_dict(),
            context=context,
            packet_number=packet_idx,
            confidence_so_far=0.0 if not self._classifications else self._cumulative_reward / len(self._classifications),
            done=False,
        )

    @property
    def state(self) -> State:
        """
        Get the current environment state.

        Returns:
            Current State with episode_id and step_count
        """
        return self._state
