from dataclasses import dataclass
from typing import List
from datetime import datetime


@dataclass
class Hypothesis:
    name: str 
    confidence: float
    evidence: List[str]   #Supporting observations
    contradictions: List[str]   #Conflicting observations
    suggested_strategies: List[str]  #Recommended next steps
    last_updated: datetime 

    def __post_init__(self):
        """Validate and normalize values"""
       
        self.confidence = max(0.0, min(1.0, self.confidence))
    
    def add_evidence(self, evidence: str):
        """Add supporting evidence and boost confidence"""
        if evidence not in self.evidence:
            self.evidence.append(evidence)
            self.confidence = min(1.0, self.confidence + 0.1)
            self.last_updated = datetime.utcnow()
    
    def add_contradiction(self, contradiction: str):
        """Add contradicting evidence and reduce confidence"""
        if contradiction not in self.contradictions:
            self.contradictions.append(contradiction)
            self.confidence = max(0.0, self.confidence - 0.15)
            self.last_updated = datetime.utcnow()
    
    def adjust_confidence(self, delta: float):
        """Manually adjust confidence by delta amount"""
        self.confidence = max(0.0, min(1.0, self.confidence + delta))
        self.last_updated = datetime.utcnow()
    
    def is_likely(self, threshold: float = 0.6) -> bool:
        """Check if hypothesis is likely true (above threshold)"""
        return self.confidence >= threshold
    
    def __str__(self):
        return f"Hypothesis({self.name}, confidence={self.confidence:.2%})"
    
    def __repr__(self):
        return (f"Hypothesis(name='{self.name}', confidence={self.confidence:.2f}, "
                f"evidence={len(self.evidence)}, contradictions={len(self.contradictions)})")