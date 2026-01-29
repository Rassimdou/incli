import re 
from typing import List , Dict , Optional , Any
from datetime import datetime 
import sys 
import os 



# ADD parent directory to path 
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from models.observation import Observation , ObservationType , confidenceLevel
from models.tech_stack import TechStack
from models.waf_profile import WAFProfile
from observer.fingerprinter import Fingerprinter
from observer.pattern_matcher import PatternMatcher




class Observer:
    """
    Extracts all possible observations from HTTP responses.
    Central analysis component that coordinates fingerprinting and pattern matching.
    """
    def __init__(self):
        self.fingerprinter = Fingerprinter()
        self.pattern_matcher = PatternMatcher()

        # Track analysis history 
        self.responses_analyzed = 0 
        self.observations_created = 0

    def analyze_response(self, response, context, payload_info=None) -> List[Observation]:
        """
        Main analysis method - extracts observations from HTTP response.
        
        Args:
            response: HTTP response object
            context: AttackContext for additional intelligence
            payload_info: Optional info about the payload that triggered this response
            
        Returns:
            List of Observation objects
        """
        self.responses_analyzed += 1
        observations = []
        
        # TODO: Implement analysis logic
        # observations.extend(self._analyze_upload_result(response))
        # observations.extend(self._analyze_error_messages(response))
        # observations.extend(self._detect_blocking_behavior(response))
        
        self.observations_created += len(observations)
        return observations

    def _analyze_upload_result(self, response) -> List[Observation]:
        """Analyze upload response for success/failure indicators"""
        # TODO: Implement upload result analysis
        return []

    def _analyze_error_messages(self, response) -> List[Observation]:
        """Extract observations from error messages in response"""
        # TODO: Implement error message analysis
        return []

    def _detect_blocking_behavior(self, response) -> List[Observation]:
        """Detect if response indicates blocking (WAF, filtering, etc.)"""
        # TODO: Implement blocking detection
        return []

    def _compare_with_baseline(self, response, baseline) -> List[Observation]:
        """Compare current response with baseline to detect differences"""
        # TODO: Implement baseline comparison
        return []

    def _detect_tech_stack(self, response) -> List[Observation]:
        """Detect technology stack from response"""
        # TODO: Implement tech stack detection
        return []

    def _detect_waf(self, response) -> List[Observation]:
        """Detect WAF presence from response"""
        # TODO: Implement WAF detection
        return []

    def _analyze_execution(self, response) -> List[Observation]:
        """Analyze if uploaded file was executed vs served statically"""
        # TODO: Implement execution analysis
        return []
