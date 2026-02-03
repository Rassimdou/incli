from typing import Dict, List
from datetime import datetime
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.hypothesis import Hypothesis
from models.observation import Observation, ObservationType
from intelligence.hypothesis_rules import HypothesisRules


class HypothesisEngine:
    """
    Intelligence engine that builds theories about the target
    
    This is the "brain" that thinks about what we've observed
    and forms educated guesses about how to proceed.
    """
    
    def __init__(self):
        
        self.rules = HypothesisRules()
        self.hypotheses_created = 0
        self.hypotheses_confirmed = 0
        self.hypotheses_rejected = 0
    
    def analyze(self, context) -> Dict[str, Hypothesis]:
        """
        Generate/update all hypotheses based on current context
        
        Args:
            context: AttackContext with observations, tech_stack, etc.
            
        Returns:
            Dict of {hypothesis_name: Hypothesis}
        """
        hypotheses = {}
        
  
        for obs in context.observations:
            new_hyps = self._generate_from_observation(obs)
            for hyp_name, hyp in new_hyps.items():
                if hyp_name in hypotheses:
                 
                    hypotheses[hyp_name].add_evidence(f"Observation: {obs.type.name}")
                else:
                    hypotheses[hyp_name] = hyp
                    self.hypotheses_created += 1
        
        #Generate hypotheses from tech stack
        if context.tech_stack:
            tech_hyps = self._generate_from_tech_stack(context.tech_stack)
            for hyp_name, hyp in tech_hyps.items():
                if hyp_name in hypotheses:
                    hypotheses[hyp_name].add_evidence(f"Tech Stack: {context.tech_stack.get_summary()}")
                else:
                    hypotheses[hyp_name] = hyp
                    self.hypotheses_created += 1
        
       
        if context.waf_profile and context.waf_profile.detected:
            waf_hyps = self._generate_from_waf(context.waf_profile)
            for hyp_name, hyp in waf_hyps.items():
                if hyp_name in hypotheses:
                    hypotheses[hyp_name].add_evidence(f"WAF: {context.waf_profile.vendor}")
                else:
                    hypotheses[hyp_name] = hyp
                    self.hypotheses_created += 1
        
        #Handle hypothesis conflicts
        hypotheses = self._resolve_conflicts(hypotheses)
        
       
        for hyp_name, hyp in hypotheses.items():
            strategies = self.rules.get_strategies_for_hypothesis(hyp_name)
            hyp.suggested_strategies = [s[0] for s in strategies]
        
        return hypotheses
    
    def update(self, context, new_observations: List[Observation]):
        """
        Update existing hypotheses based on new evidence
        
        Args:
            context: AttackContext with current hypotheses
            new_observations: New observations to process
        """
        for obs in new_observations:
           
            suggested_hyps = self.rules.get_hypotheses_for_observation(obs.type)
            
            for hyp_name, initial_confidence in suggested_hyps:
                if hyp_name in context.hypotheses:
                    
                    hyp = context.hypotheses[hyp_name]
                    
                 
                    if self._supports_hypothesis(obs, hyp):
                        hyp.add_evidence(f"{obs.type.name}: {', '.join(obs.evidence[:2])}")
                        self.hypotheses_confirmed += 1
                    elif self._contradicts_hypothesis(obs, hyp):
                        hyp.add_contradiction(f"{obs.type.name}: {', '.join(obs.evidence[:2])}")
                        self.hypotheses_rejected += 1
                else:
                    
                    new_hyp = Hypothesis(
                        name=hyp_name,
                        confidence=initial_confidence,
                        evidence=[f"{obs.type.name}: {', '.join(obs.evidence[:2])}"],
                        suggested_strategies=[]
                    )
                    context.hypotheses[hyp_name] = new_hyp
                    self.hypotheses_created += 1
    
    def _generate_from_observation(self, obs: Observation) -> Dict[str, Hypothesis]:
        """
        Generate hypotheses from a single observation
        
        Args:
            obs: Observation to analyze
            
        Returns:
            Dict of {hypothesis_name: Hypothesis}
        """
        hypotheses = {}
        
      
        suggested = self.rules.get_hypotheses_for_observation(obs.type)
        
        for hyp_name, initial_confidence in suggested:
            
            adjusted_confidence = initial_confidence * obs.get_confidence_score()
            
            hypotheses[hyp_name] = Hypothesis(
                name=hyp_name,
                confidence=adjusted_confidence,
                evidence=[f"{obs.type.name}: {', '.join(obs.evidence[:2])}"],
                suggested_strategies=[]
            )
        
        return hypotheses
    
    def _generate_from_tech_stack(self, tech_stack) -> Dict[str, Hypothesis]:
        """
        Generate hypotheses from detected tech stack
        
        Args:
            tech_stack: TechStack object
            
        Returns:
            Dict of {hypothesis_name: Hypothesis}
        """
        hypotheses = {}
        
      
        tech_hyps = self.rules.get_hypotheses_for_tech_stack(
            server=tech_stack.web_server,
            language=tech_stack.language,
            language_version=tech_stack.language_version
        )
        
        for hyp_name, confidence in tech_hyps:
          
            adjusted_confidence = confidence * tech_stack.confidence
            
            hypotheses[hyp_name] = Hypothesis(
                name=hyp_name,
                confidence=adjusted_confidence,
                evidence=[f"Tech Stack: {tech_stack.get_summary()}"],
                suggested_strategies=[]
            )
        
        return hypotheses
    
    def _generate_from_waf(self, waf_profile) -> Dict[str, Hypothesis]:
        """
        Generate hypotheses from WAF detection
        
        Args:
            waf_profile: WAFProfile object
            
        Returns:
            Dict of {hypothesis_name: Hypothesis}
        """
        hypotheses = {}
        
        if waf_profile.detected:
            hypotheses["waf_present"] = Hypothesis(
                name="waf_present",
                confidence=waf_profile.confidence,
                evidence=[f"WAF: {waf_profile.vendor}", *waf_profile.signatures],
                suggested_strategies=["encoding_bypass", "fragmentation"]
            )
            
            hypotheses["bypass_required"] = Hypothesis(
                name="bypass_required",
                confidence=waf_profile.confidence * 0.9,
                evidence=[f"WAF blocking: {waf_profile.vendor}"],
                suggested_strategies=waf_profile.bypass_techniques[:3]
            )
        
        return hypotheses
    
    def _resolve_conflicts(self, hypotheses: Dict[str, Hypothesis]) -> Dict[str, Hypothesis]:
        """
        Handle conflicting hypotheses (e.g., blacklist vs whitelist)
        
        Args:
            hypotheses: Current hypotheses
            
        Returns:
            Hypotheses with conflicts resolved
        """
        for hyp_name, hyp in list(hypotheses.items()):
           
            conflicts = self.rules.get_conflicting_hypotheses(hyp_name)
            
            for conflict_name in conflicts:
                if conflict_name in hypotheses:
                    conflict_hyp = hypotheses[conflict_name]
                    
                    
                    if hyp.confidence > conflict_hyp.confidence:
                        
                        conflict_hyp.confidence *= 0.5
                        conflict_hyp.add_contradiction(f"Conflicts with {hyp_name}")
                    else:
                    
                        hyp.confidence *= 0.5
                        hyp.add_contradiction(f"Conflicts with {conflict_name}")
        
        return hypotheses
    
    def _supports_hypothesis(self, obs: Observation, hyp: Hypothesis) -> bool:
        """
        Check if observation supports hypothesis
        
        Args:
            obs: Observation
            hyp: Hypothesis
            
        Returns:
            True if observation supports hypothesis
        """
        
        suggested = self.rules.get_hypotheses_for_observation(obs.type)
        suggested_names = [h[0] for h in suggested]
        
        return hyp.name in suggested_names
    
    def _contradicts_hypothesis(self, obs: Observation, hyp: Hypothesis) -> bool:
        """
        Check if observation contradicts hypothesis
        
        Args:
            obs: Observation
            hyp: Hypothesis
            
        Returns:
            True if observation contradicts hypothesis
        """
        
        contradiction_map = {
            ObservationType.NULL_BYTE_SUCCESS: ["php_8_or_above", "null_byte_not_vulnerable"],
            ObservationType.CODE_EXECUTION_DETECTED: ["code_execution_impossible"],
            ObservationType.WAF_DETECTED: ["no_waf"],
        }
        
        contradicted = contradiction_map.get(obs.type, [])
        return hyp.name in contradicted
    
    def get_top_hypotheses(self, hypotheses: Dict[str, Hypothesis], n: int = 3) -> List[Hypothesis]:
        """
        Get top N hypotheses by confidence
        
        Args:
            hypotheses: All hypotheses
            n: Number to return
            
        Returns:
            List of top hypotheses
        """
        sorted_hyps = sorted(
            hypotheses.values(),
            key=lambda h: h.confidence,
            reverse=True
        )
        return sorted_hyps[:n]
    
    def explain_hypothesis(self, hyp: Hypothesis) -> str:
        """
        Generate human-readable explanation of hypothesis
        
        Args:
            hyp: Hypothesis to explain
            
        Returns:
            Explanation string
        """
        lines = [
            f"Hypothesis: {hyp.name}",
            f"Confidence: {hyp.confidence:.0%}",
            f"",
            f"Supporting Evidence ({len(hyp.evidence)} items):",
        ]
        
        for i, evidence in enumerate(hyp.evidence[:5], 1):
            lines.append(f"  {i}. {evidence}")
        
        if len(hyp.evidence) > 5:
            lines.append(f"  ... and {len(hyp.evidence) - 5} more")
        
        if hyp.contradictions:
            lines.append(f"")
            lines.append(f"Contradicting Evidence ({len(hyp.contradictions)} items):")
            for i, contradiction in enumerate(hyp.contradictions[:3], 1):
                lines.append(f"  {i}. {contradiction}")
        
        if hyp.suggested_strategies:
            lines.append(f"")
            lines.append(f"Suggested Strategies:")
            for strategy in hyp.suggested_strategies[:5]:
                lines.append(f"  - {strategy}")
        
        return "\n".join(lines)
    
    def get_statistics(self) -> Dict[str, int]:
        """
        Get engine statistics
        
        Returns:
            Dict with statistics
        """
        return {
            "hypotheses_created": self.hypotheses_created,
            "hypotheses_confirmed": self.hypotheses_confirmed,
            "hypotheses_rejected": self.hypotheses_rejected,
        }