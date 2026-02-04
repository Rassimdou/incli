from dataclasses import dataclass
from typing import List
from strategies.base import Strategy


@dataclass
class RankedStrategy:
    strategy: Strategy
    score : float
    reasoning: str
    hypothesis_matches: List[str] #which hypothesis it matches
    confidence_factors: dict = None

    def get_score_percentage(self) -> str:
        return f"{self.score:.1%}"
    
    def get_confidence_level(self) -> str:
        if self.score >= 0.8: return "CRITICAL"
        if self.score >= 0.6: return "HIGH"
        if self.score >= 0.4: return "MEDIUM"
        return "LOW"