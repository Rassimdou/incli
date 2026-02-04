from dataclasses import dataclass, field
from typing import List
from datetime import datetime


@dataclass
class Hypothesis:
    name: str 
    confidence: float
    evidence: List[str] = field(default_factory=list)   #Supporting observations
    contradictions: List[str] = field(default_factory=list)   #Conflicting observations
    suggested_strategies: List[str] = field(default_factory=list)  #Recommended next steps
    last_updated: datetime = field(default_factory=datetime.utcnow) 

    def __post_init__(self):
        
       
        self.confidence = max(0.0, min(1.0, self.confidence))
    
    def add_evidence(self, evidence: str):
        
        if evidence not in self.evidence:
            self.evidence.append(evidence)
            self.confidence = min(1.0, self.confidence + 0.1)
            self.last_updated = datetime.utcnow()
    
    def add_contradiction(self, contradiction: str):
        
        if contradiction not in self.contradictions:
            self.contradictions.append(contradiction)
            self.confidence = max(0.0, self.confidence - 0.15)
            self.last_updated = datetime.utcnow()
    
    def adjust_confidence(self, delta: float):
       
        self.confidence = max(0.0, min(1.0, self.confidence + delta))
        self.last_updated = datetime.utcnow()
    
    def is_likely(self, threshold: float = 0.6) -> bool:
       
        return self.confidence >= threshold
    
    def __str__(self):
        return f"Hypothesis({self.name}, confidence={self.confidence:.2%})"
    
    def __repr__(self):
        return (f"Hypothesis(name='{self.name}', confidence={self.confidence:.2f}, "
                f"evidence={len(self.evidence)}, contradictions={len(self.contradictions)})")