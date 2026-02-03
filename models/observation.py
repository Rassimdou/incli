"""
Enhanced Observation Model

Extended with new observation types for upload vulnerabilities.
Maintains compatibility with your existing code.
"""

from enum import Enum, auto
from dataclasses import dataclass
from typing import List


class ObservationType(Enum):
 
    FILE_READ_CONFIRMED = auto()
    FILTER_DOT_BLOCKED = auto()
    FILTER_SLASH_BLOCKED = auto()
    EXTENSION_FORCED = auto()
    NORMALIZATION_DETECTED = auto()
    NULL_BYTE_REMOVED = auto()
    CODE_EXECUTION_DETECTED = auto()
    ERROR_MESSAGE_DETECTED = auto()
    UPLOAD_SUCCESS = auto()
    UPLOAD_REJECTED = auto()
   
    
    TECH_STACK_DETECTED = auto()
    WAF_DETECTED = auto()
    FILTER_DETECTED = auto()
    BASELINE_ESTABLISHED = auto()
    HYPOTHESIS_CONFIRMED = auto()
    HYPOTHESIS_REJECTED = auto()
    STRUCTURAL_CHANGE = auto()
    
    NULL_BYTE_SUCCESS = auto()
    DOUBLE_EXTENSION_SUCCESS = auto()
    CASE_MANIPULATION_SUCCESS = auto()
    POLYGLOT_SUCCESS = auto()
    MAGIC_BYTES_SUCCESS = auto()
   


class ConfidenceLevel(Enum):
  
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    
    def to_float(self) -> float:
        """Convert to numeric confidence (0.0 to 1.0)"""
        mapping = {
            ConfidenceLevel.LOW: 0.3,
            ConfidenceLevel.MEDIUM: 0.6,
            ConfidenceLevel.HIGH: 0.9
        }
        return mapping.get(self, 0.5)
    
    @staticmethod
    def from_float(value: float) -> 'ConfidenceLevel':
        """Convert numeric confidence to ConfidenceLevel"""
        if value >= 0.75:
            return ConfidenceLevel.HIGH
        elif value >= 0.45:
            return ConfidenceLevel.MEDIUM
        else:
            return ConfidenceLevel.LOW


@dataclass
class Observation:

    
    type: ObservationType
    confidence: ConfidenceLevel
    evidence: List[str]
    uploaded_filename: str = None
    stored_filename: str = None
    file_url: str = None
    execution_confirmed: bool = False
    metadata: dict = None

    
    def __post_init__(self):

        if self.metadata is None:
            self.metadata = {}
    
    def get_confidence_score(self) -> float:
        """Get numeric confidence score (0.0 to 1.0)"""
        return self.confidence.to_float()
    
    def is_high_confidence(self) -> bool:
        
        return self.confidence == ConfidenceLevel.HIGH
    
    def is_security_critical(self) -> bool:

        critical_types = [
            ObservationType.CODE_EXECUTION_DETECTED,
            ObservationType.FILE_READ_CONFIRMED,
            ObservationType.NULL_BYTE_SUCCESS,
            ObservationType.DOUBLE_EXTENSION_SUCCESS,
            ObservationType.POLYGLOT_SUCCESS,
        ]
        return self.type in critical_types
    
    def add_evidence(self, evidence: str):
      
        if evidence not in self.evidence:
            self.evidence.append(evidence)
    
    def __str__(self):
        return f"Observation({self.type.name}, confidence={self.confidence.name})"
    
    def __repr__(self):
        return (f"Observation(type={self.type.name}, confidence={self.confidence.name}, "
                f"evidence={len(self.evidence)} items)")