# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
Graders for Network Packet Anomaly Detection Tasks.

Implements deterministic grading for 3 difficulty levels.
"""

from typing import List, Tuple
from dataclasses import dataclass


@dataclass
class ClassificationResult:
    """Result of a single packet classification."""
    predicted_label: str  # "normal" or "anomaly"
    predicted_confidence: float
    actual_label: str  # "normal" or "anomaly"
    is_correct: bool
    is_tp: bool  # True Positive
    is_tn: bool  # True Negative
    is_fp: bool  # False Positive
    is_fn: bool  # False Negative


class TaskGrader:
    """Base class for task grading."""

    def __init__(self):
        self.name = "Task"
        self.difficulty = "unknown"

    def evaluate(self, classifications: List[ClassificationResult]) -> float:
        """
        Evaluate agent performance on a task.
        
        Returns:
            Score between 0.0 and 1.0
        """
        raise NotImplementedError


class Task1Grader(TaskGrader):
    """
    Task 1: Easy - Binary Normal/Anomaly Detection (DDoS)
    
    Simple DDoS detection with obvious patterns (high packet rate, low entropy).
    """

    def __init__(self):
        super().__init__()
        self.name = "Task 1: DDoS Detection"
        self.difficulty = "easy"

    def evaluate(self, classifications: List[ClassificationResult]) -> float:
        """
        Evaluate using F1-score (balance of precision and recall).
        
        For a simple DDoS task with obvious patterns:
        - Expected to achieve > 0.85 F1 for success
        """
        if not classifications:
            return 0.0

        tp = sum(1 for c in classifications if c.is_tp)
        tn = sum(1 for c in classifications if c.is_tn)
        fp = sum(1 for c in classifications if c.is_fp)
        fn = sum(1 for c in classifications if c.is_fn)

        # Precision = TP / (TP + FP)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

        # Recall = TP / (TP + FN)
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        # F1 = 2 * (Precision * Recall) / (Precision + Recall)
        f1 = (
            2 * (precision * recall) / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        # Clamp to [0, 1]
        return max(0.0, min(1.0, f1))


class Task2Grader(TaskGrader):
    """
    Task 2: Medium - Multi-Attack Classification (DDoS + Port Scan + C2 + Normal)
    
    Requires distinguishing between attack types and penalizes false positives
    (analyst fatigue from too many alerts).
    """

    def __init__(self):
        super().__init__()
        self.name = "Task 2: Multi-Attack Detection"
        self.difficulty = "medium"

    def evaluate(self, classifications: List[ClassificationResult]) -> float:
        """
        Macro-averaged F1 across attack types, with penalty for high false positive rate.
        
        Metric: F1 * (1 - false_positive_rate_penalty)
        """
        if not classifications:
            return 0.0

        tp = sum(1 for c in classifications if c.is_tp)
        tn = sum(1 for c in classifications if c.is_tn)
        fp = sum(1 for c in classifications if c.is_fp)
        fn = sum(1 for c in classifications if c.is_fn)

        total = tp + tn + fp + fn

        # Precision (avoid false positives)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

        # Recall (catch actual attacks)
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        # F1 score
        f1 = (
            2 * (precision * recall) / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        # False positive rate penalty
        fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fp_penalty = fp_rate * 0.3  # Up to 30% penalty

        score = f1 * (1.0 - fp_penalty)
        return max(0.0, min(1.0, score))


class Task3Grader(TaskGrader):
    """
    Task 3: Hard - Adversarial/Encrypted + Low-Volume Attacks
    
    Includes legitimate encrypted traffic (high entropy) that agent must not
    flag as anomaly. Also includes stealthy, low-volume C2 attacks.
    
    Metric: Recall - 0.3 * FalsePositiveRate
    Encourages catching attacks while avoiding false positives on encrypted legit traffic.
    """

    def __init__(self):
        super().__init__()
        self.name = "Task 3: Adversarial Detection"
        self.difficulty = "hard"

    def evaluate(self, classifications: List[ClassificationResult]) -> float:
        """
        Maximize (Recall - 0.3 * FalsePositiveRate).
        
        Success if score >= 0.75 or precision > 0.90 AND recall > 0.70
        """
        if not classifications:
            return 0.0

        tp = sum(1 for c in classifications if c.is_tp)
        tn = sum(1 for c in classifications if c.is_tn)
        fp = sum(1 for c in classifications if c.is_fp)
        fn = sum(1 for c in classifications if c.is_fn)

        # Recall: catch actual attacks
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        # False positive rate
        fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        # Main metric
        score = recall - (0.3 * fp_rate)

        # Bonus for high precision + decent recall
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        if precision > 0.90 and recall > 0.70:
            score = min(1.0, score + 0.1)  # +10% bonus

        return max(0.0, min(1.0, score))


class GraderFactory:
    """Factory for creating graders."""

    GRADERS = {
        1: Task1Grader,
        2: Task2Grader,
        3: Task3Grader,
    }

    @staticmethod
    def get_grader(task_number: int) -> TaskGrader:
        """Get grader for a specific task."""
        if task_number not in GraderFactory.GRADERS:
            raise ValueError(f"Unknown task number: {task_number}")
        return GraderFactory.GRADERS[task_number]()

    @staticmethod
    def grade_all_tasks(
        all_classifications: dict,
    ) -> Tuple[float, float, float, float]:
        """
        Grade all 3 tasks.
        
        Args:
            all_classifications: Dict mapping task_number -> List[ClassificationResult]
        
        Returns:
            Tuple of (task1_score, task2_score, task3_score, overall_score)
        """
        scores = {}
        for task_num in [1, 2, 3]:
            grader = GraderFactory.get_grader(task_num)
            classifications = all_classifications.get(task_num, [])
            scores[task_num] = grader.evaluate(classifications)

        # Overall is average of 3 tasks
        overall = sum(scores.values()) / 3.0

        return scores[1], scores[2], scores[3], overall
