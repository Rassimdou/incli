from dataclasses import dataclass
from typing import List, Optional


@dataclass 
class WAFProfile:
    detected: bool
    vendor : Optional[str]  # Modsecurity, Cloudflare, AWS WAF, etc.
    confidence: float
    signatures: List[str] # what gave it away
    bypass_techniques: List[str] #KNOWN bypass for this WAF