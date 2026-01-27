from enum import Enum , auto 
from dataclass import dataclass 
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




class confidenceLevel(Enum):
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()



@dataclass
class Observation:
    type: ObservationType
    confidence: confidenceLevel
    evidence: List[str]