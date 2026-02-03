from typing import List , Dict
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.ranked_strategy import RankedStrategy
from intelligence.hypothesis_rules import HypothesisRules


class StrategyRanker: 

    def __init__(self):
        self.rules = HypothesisRules()
        self.rankings_generated = 0

    def rank(self, strategies :List, context ) -> List[RankedStrategy]:
        ranked = []

        for strategy in strategies:
            # Calculate likelihood score
            score = self._calculate_score(strategy, context)
            
            #find Matching hypotheses 
            matches = self._get_matching_hypotheses(strategy, context)
            
