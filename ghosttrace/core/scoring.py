from __future__ import annotations

from typing import Dict, Any, List
import math


# Legacy helpers retained for compatibility
def compute_confidence(score: float, max_score: float = 100.0) -> float:
    return min(max(score / max_score * 100.0, 0.0), 100.0)


def severity_from_confidence(confidence: float) -> str:
    if confidence >= 85:
        return "high"
    if confidence >= 55:
        return "medium"
    return "low"


def score_exposure(result: Dict[str, object]) -> float:
    base = 20.0
    if result.get("status") == "found":
        base += 40.0
    if result.get("category") == "breaches":
        base += 20.0
    return compute_confidence(base, max_score=100.0)


# New ScoringEngine for correlation
DEFAULT_WEIGHTS = {
    'exact_email': 3.0,
    'avatar_hash': 2.5,
    'same_profile_url': 2.0,
    'same_bio': 1.5,
    'username_similarity': 1.2,
    'transliteration_match': 1.2,
    'display_name_similarity': 0.8,
    'found_status': 1.0,
}


class ScoringEngine:
    def __init__(self, weights: Dict[str, float] = None) -> None:
        self.weights = {**DEFAULT_WEIGHTS, **(weights or {})}

    def weight(self, key: str) -> float:
        return float(self.weights.get(key, 0.0))

    def score_from_evidence(self, evidences: List[Dict[str, Any]]) -> float:
        """Combine evidence items into a final confidence score (0-100).

        Each evidence item should include a `type` key mapping to a weightable factor.
        """
        if not evidences:
            return 0.0
        score = 0.0
        for ev in evidences:
            t = ev.get('type')
            score += self.weight(t) * float(ev.get('value', 1.0))

        # normalize: map accumulated weight to 0-100 using a soft cap
        # use log scale to avoid runaway values
        normalized = 100.0 * (1 - math.exp(-score / 3.0))
        return round(min(99.9, normalized), 2)

    def make_evidence(self, type: str, checker: str, details: str = '', value: float = 1.0) -> Dict[str, Any]:
        return {'type': type, 'checker': checker, 'details': details, 'value': value}
