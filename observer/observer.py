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
    Extracts all possible observations
    """
    def __init__(self):
        self.fingerprinter = Fingerprinter()
        self.pattern_matcher = PatternMatcher()

        #Track analysis history 
        self.response_abalyzed = 0 
        self.observations_created = 0
    def analyze_response(self, response, context, payload_info = None) ->List[Obsercation]

        #Analysis methods (each returns observations)
        def _analyze_upload_result(self, response) -> List[Observation]
        def _analyze_error_messages(self, response) -> List[Observation]
        def _detect_blocking_behavior(self, response) -> List[Observation]
        def _compare_with_baseline(self, response, baseline) -> List[Observation]
        def _detect_tech_stack(self, response) -> List[Observation]
        def _detect_waf(self, response) -> List[Observation]
        def _analyze_execution(self, response) -> List[Observation]
