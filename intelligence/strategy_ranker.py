from typing import List, Dict
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.ranked_strategy import RankedStrategy
from intelligence.hypothesis_rules import HypothesisRules


class StrategyRanker:
    
    def __init__(self):
        self.rules = HypothesisRules()
        self.rankings_generated = 0
    
    def rank(self, strategies: List, context) -> List[RankedStrategy]:
        """
        Main ranking function
        
        Args:
            strategies: List of Strategy objects to rank
            context: AttackContext with current intelligence
            
        Returns:
            List of RankedStrategy objects, sorted by score (highest first)
        """
        ranked = []
        
        for strategy in strategies:
          
            score = self._calculate_score(strategy, context)
            
            reasoning = self._generate_reasoning(strategy, context, score)
            
            matches = self._get_matching_hypotheses(strategy, context)
            
            factors = self._get_confidence_factors(strategy, context)
            
            ranked.append(RankedStrategy(
                strategy=strategy,
                score=score,
                reasoning=reasoning,
                hypothesis_matches=matches,
                confidence_factors=factors
            ))
        
        # Sort by score (highest first)
        ranked.sort(key=lambda x: x.score, reverse=True)
        
        self.rankings_generated += 1
        
        return ranked
    
    def _calculate_score(self, strategy, context) -> float:
        """
        Calculate likelihood score for a strategy
        
        Factors:
        1. Hypothesis matching (main factor)
        2. Tech stack compatibility
        3. Previous attempt results
        4. Strategy base confidence
        
        Args:
            strategy: Strategy to score
            context: Current context
            
        Returns:
            Score from 0.0 to 1.0
        """
        score = 0.0
        
    
        hypothesis_score = self._calculate_hypothesis_score(strategy, context)
        score += hypothesis_score * 0.5
        
        
        tech_score = self._calculate_tech_score(strategy, context)
        score += tech_score * 0.3
        
        
        history_score = self._calculate_history_score(strategy, context)
        score += history_score * 0.15
        
       
        base_score = strategy.confidence_gain if hasattr(strategy, 'confidence_gain') else 0.5
        score += base_score * 0.05
        
        # Normalize to 0-1 range
        score = max(0.0, min(1.0, score))
        
        return score
    
    def _calculate_hypothesis_score(self, strategy, context) -> float:
        """
        Score based on matching hypotheses
        
        Args:
            strategy: Strategy to score
            context: Current context
            
        Returns:
            Score from 0.0 to 1.0
        """
        if not hasattr(strategy, 'targets_hypotheses') or not strategy.targets_hypotheses:
            return 0.5  # Neutral if no targeting info
        
        total_confidence = 0.0
        matched_count = 0
        
        for hyp_name in strategy.targets_hypotheses:
            if hyp_name in context.hypotheses:
                hyp = context.hypotheses[hyp_name]
                total_confidence += hyp.confidence
                matched_count += 1
        
        if matched_count == 0:
            return 0.3  # Low score if no hypotheses match
        
       
        avg_confidence = total_confidence / matched_count
        
        
        if matched_count >= 2:
            avg_confidence *= 1.2
        
        return min(1.0, avg_confidence)
    
    def _calculate_tech_score(self, strategy, context) -> float:
        """
        Score based on tech stack compatibility
        
        Args:
            strategy: Strategy to score
            context: Current context
            
        Returns:
            Score from 0.0 to 1.0
        """
        if not context.tech_stack:
            return 0.5  # Neutral if no tech stack info
        
        tech_stack = context.tech_stack
        score = 0.5  # Start neutral
        
        # Check if strategy has tech requirements
        if hasattr(strategy, 'tech_requirements'):
            reqs = strategy.tech_requirements
            
            # Check language requirement
            if 'language' in reqs:
                required_langs = reqs['language']
                if tech_stack.language and tech_stack.language.lower() in [l.lower() for l in required_langs]:
                    score += 0.3
                else:
                    score -= 0.3
            
            # Check version requirements
            if 'version_max' in reqs and tech_stack.language_version:
                max_version = reqs['version_max']
                try:
                    current = float(tech_stack.language_version.split('.')[0])
                    max_ver = float(max_version.split('.')[0])
                    
                    if current < max_ver:
                        score += 0.2
                    else:
                        score -= 0.4  # Penalize heavily if version too high
                except:
                    pass
            
            if 'version_min' in reqs and tech_stack.language_version:
                min_version = reqs['version_min']
                try:
                    current = float(tech_stack.language_version.split('.')[0])
                    min_ver = float(min_version.split('.')[0])
                    
                    if current >= min_ver:
                        score += 0.2
                    else:
                        score -= 0.4
                except:
                    pass
        
        # Get tech-specific boosts from rules
        boosts = self.rules.get_strategy_boost_for_tech(tech_stack)
        if strategy.name in boosts:
            score *= boosts[strategy.name]
        
        return max(0.0, min(1.0, score))
    
    def _calculate_history_score(self, strategy, context) -> float:
        """
        Score based on previous attempt results
        
        Args:
            strategy: Strategy to score
            context: Current context
            
        Returns:
            Score from 0.0 to 1.0
        """
        if not hasattr(context, 'strategy_results') or not context.strategy_results:
            return 0.5  # Neutral if no history
        
        strategy_name = strategy.name
        
        if strategy_name not in context.strategy_results:
            return 0.6  # Slight boost for untried strategies
        
        # Check previous result
        from strategies.base import StrategyStatus
        
        result = context.strategy_results[strategy_name]
        
        if result == StrategyStatus.SUCCESS:
            return 0.9 
        elif result == StrategyStatus.FAILURE:
            return 0.1  
        elif result == StrategyStatus.INCONCLUSIVE:
            return 0.4  
        
        return 0.5
    
    def _generate_reasoning(self, strategy, context, score: float) -> str:
        """
        Generate human-readable explanation of the score
        
        Args:
            strategy: Strategy being scored
            context: Current context
            score: Calculated score
            
        Returns:
            Explanation string
        """
        reasons = []
        
        
        if hasattr(strategy, 'targets_hypotheses'):
            matched = []
            for hyp_name in strategy.targets_hypotheses:
                if hyp_name in context.hypotheses:
                    hyp = context.hypotheses[hyp_name]
                    matched.append(f"{hyp_name} ({hyp.confidence:.0%})")
            
            if matched:
                reasons.append(f"Matches hypotheses: {', '.join(matched)}")
            else:
                reasons.append("No matching hypotheses (exploratory)")
        
        
        if context.tech_stack:
            tech_info = []
            if context.tech_stack.language:
                tech_info.append(context.tech_stack.language)
            if context.tech_stack.language_version:
                tech_info.append(context.tech_stack.language_version)
            if context.tech_stack.web_server:
                tech_info.append(context.tech_stack.web_server)
            
            if tech_info:
                reasons.append(f"Tech stack: {' '.join(tech_info)}")
        
        # Previous attempts
        if hasattr(context, 'strategy_results') and strategy.name in context.strategy_results:
            result = context.strategy_results[strategy.name]
            reasons.append(f"Previously attempted: {result}")
        else:
            reasons.append("Not yet attempted")
        
        # Overall assessment
        if score >= 0.8:
            assessment = "Very high confidence"
        elif score >= 0.6:
            assessment = "Good confidence"
        elif score >= 0.4:
            assessment = "Medium confidence"
        else:
            assessment = "Low confidence"
        
        reasons.insert(0, assessment)
        
        return " | ".join(reasons)
    
    def _get_matching_hypotheses(self, strategy, context) -> List[str]:
        """
        Get list of hypothesis names that match this strategy
        
        Args:
            strategy: Strategy to check
            context: Current context
            
        Returns:
            List of matching hypothesis names
        """
        matches = []
        
        if hasattr(strategy, 'targets_hypotheses'):
            for hyp_name in strategy.targets_hypotheses:
                if hyp_name in context.hypotheses:
                    matches.append(hyp_name)
        
        return matches
    
    def _get_confidence_factors(self, strategy, context) -> Dict[str, float]:
        """
        Get breakdown of confidence factors
        
        Args:
            strategy: Strategy to analyze
            context: Current context
            
        Returns:
            Dict of factor names to scores
        """
        factors = {}
        
        factors['hypothesis_match'] = self._calculate_hypothesis_score(strategy, context)
        factors['tech_compatibility'] = self._calculate_tech_score(strategy, context)
        factors['history'] = self._calculate_history_score(strategy, context)
        
        if hasattr(strategy, 'confidence_gain'):
            factors['base_confidence'] = strategy.confidence_gain
        
        return factors
    
    def get_best_strategy(self, strategies: List, context) -> RankedStrategy:
        """
        Get the single best strategy
        
        Args:
            strategies: List of strategies
            context: Current context
            
        Returns:
            Top ranked strategy
        """
        ranked = self.rank(strategies, context)
        return ranked[0] if ranked else None
    
    def get_high_confidence_strategies(self, strategies: List, context, 
                                      threshold: float = 0.7) -> List[RankedStrategy]:
        """
        Get only high-confidence strategies
        
        Args:
            strategies: List of strategies
            context: Current context
            threshold: Minimum confidence threshold
            
        Returns:
            List of high-confidence strategies
        """
        ranked = self.rank(strategies, context)
        return [r for r in ranked if r.score >= threshold]
    
    def explain_ranking(self, ranked_strategies: List[RankedStrategy]) -> str:
        """
        Generate detailed explanation of ranking
        
        Args:
            ranked_strategies: List of ranked strategies
            
        Returns:
            Multi-line explanation
        """
        lines = ["Strategy Ranking:"]
        lines.append("=" * 70)
        
        for i, ranked in enumerate(ranked_strategies, 1):
            lines.append(f"\n{i}. {ranked.strategy.name}")
            lines.append(f"   Score: {ranked.get_score_percentage()} ({ranked.get_confidence_level()})")
            lines.append(f"   Reasoning: {ranked.reasoning}")
            
            if ranked.hypothesis_matches:
                lines.append(f"   Matches: {', '.join(ranked.hypothesis_matches)}")
        
        return "\n".join(lines)
    
    def get_statistics(self) -> Dict[str, int]:
        """Get ranker statistics"""
        return {
            "rankings_generated": self.rankings_generated
        }