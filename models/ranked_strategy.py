from dataclasses import dataclass
from typing import List
from strategies.base import Strategy


@dataclass
class RankedStrategy:
    stratrgy: Strategy
    score : float
    reasoning: str
    hypothesis_matches: List[str] #which hypothesis it matches