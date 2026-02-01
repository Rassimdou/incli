from enum import Enum , auto 
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
    TECH_STACK_DETECTED = auto()
    WAF_DETECTED = auto()
    BASELINE_ESTABLISHED = auto()
    HYPOTHESIS_CONFIRMED = auto()
    HYPOTHESIS_REJECTED = auto()


    UPLOAD_SUCCESS = auto()
    """File upload succeeded"""
    
    UPLOAD_REJECTED = auto()
    """File upload was rejected"""
    
    TECH_STACK_DETECTED = auto()
    """Technology stack fingerprinted"""
    
    WAF_DETECTED = auto()
    """Web Application Firewall detected"""
    
    FILTER_DETECTED = auto()
    """Generic filter detected"""
    
    BASELINE_ESTABLISHED = auto()
    """Baseline behavior recorded"""
    
    HYPOTHESIS_CONFIRMED = auto()
    """A hypothesis was confirmed by evidence"""
    
    HYPOTHESIS_REJECTED = auto()
    """A hypothesis was rejected by evidence"""
    
    STRUCTURAL_CHANGE = auto()
    """Significant change in response structure"""
    
    # ===== Strategy-Specific Types =====
    NULL_BYTE_SUCCESS = auto()
    """Null byte bypass succeeded"""
    
    DOUBLE_EXTENSION_SUCCESS = auto()
    """Double extension bypass succeeded"""
    
    CASE_MANIPULATION_SUCCESS = auto()
    """Case manipulation bypass succeeded"""
    
    POLYGLOT_SUCCESS = auto()
    """Polyglot file bypass succeeded"""
    
    MAGIC_BYTES_SUCCESS = auto()
    """Magic bytes bypass succeeded"""


class ConfidenceLevel(Enum):
    """
    Confidence level in an observation
    """
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
































