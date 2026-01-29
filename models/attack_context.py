from dataclasses import dataclass , field
from typing import List , Dict, Optional
import sys 
import os 

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.attack_state import AttackState
from models.observation import Observation
from models.capabilities import CapabilityProfile
from models.filters import FilterProfile
from models.hypothesis import Hypothesis
from models.tech_stack import TechStack
from models.waf_profile import WAFProfile


@dataclass
class AttackContext:
    target_url: str
    parameter: str
    state: AttackState = AttackState.TARGET_READY
    observations: List[Observation] = field(default_factory=list)
    capabilities: CapabilityProfile = field(default_factory=CapabilityProfile)
    filters: FilterProfile = field(default_factory=FilterProfile)
    strategy_history: List[str] = field(default_factory=list)
    """List of strategies that have been tried"""
    
    
    hypotheses: Dict[str, Hypothesis] = field(default_factory=dict) #Current hypotheses about the target
    tech_stack: Optional[TechStack] = None #Detected technology stack
    waf_profile: Optional[WAFProfile] = None #Detected WAF information
    baseline_response: Optional[any] = None #Response from baseline (safe) upload
    strategy_results: Dict[str, str] = field(default_factory=dict) #Results of executed strategies {strategy_name: StrategyStatus}
    secret: Optional[str] = None  #Extracted secret (for labs/CTFs)
    last_response: Optional[str] = None   #Last response text (for analysis)
    metadata: Dict[str, any] = field(default_factory=dict)  #Additional metadata
    
    
    def add_observation(self, observation: Observation):
        """
        Add an observation to the context
        
        Args:
            observation: Observation to add
        """
        self.observations.append(observation)
        
        # Update state based on observation type if needed
        from models.observation import ObservationType
        
        if observation.type == ObservationType.CODE_EXECUTION_DETECTED:
            self.state = AttackState.CODE_EXECUTION
            self.capabilities.can_execute_code = True
        
        elif observation.type == ObservationType.FILE_READ_CONFIRMED:
            self.capabilities.can_read_files = True
    
    def add_hypothesis(self, name: str, hypothesis: Hypothesis):
        """
        Add or update a hypothesis
        
        Args:
            name: Hypothesis name
            hypothesis: Hypothesis object
        """
        self.hypotheses[name] = hypothesis
    
    def get_top_hypotheses(self, n: int = 3) -> List[Hypothesis]:
        """
        Get top N hypotheses by confidence
        
        Args:
            n: Number of hypotheses to return
            
        Returns:
            List of top hypotheses
        """
        sorted_hyps = sorted(
            self.hypotheses.values(),
            key=lambda h: h.confidence,
            reverse=True
        )
        return sorted_hyps[:n]
    
    def update_hypothesis_confidence(self, name: str, delta: float):
        """
        Adjust hypothesis confidence
        
        Args:
            name: Hypothesis name
            delta: Amount to adjust confidence by
        """
        if name in self.hypotheses:
            self.hypotheses[name].adjust_confidence(delta)
    
    def record_strategy(self, strategy_name: str, result: str):
        """
        Record result of a strategy execution
        
        Args:
            strategy_name: Name of strategy
            result: StrategyStatus as string
        """
        self.strategy_results[strategy_name] = result
        
        if strategy_name not in self.strategy_history:
            self.strategy_history.append(strategy_name)
    
    def get_observation_count(self) -> int:
        return len(self.observations)
    
    def get_hypothesis_count(self) -> int:
        return len(self.hypotheses)
    
    def get_high_confidence_hypotheses(self, threshold: float = 0.7) -> List[Hypothesis]:
        """
        Get hypotheses with high confidence
        
        Args:
            threshold: Minimum confidence threshold
            
        Returns:
            List of high-confidence hypotheses
        """
        return [h for h in self.hypotheses.values() if h.confidence >= threshold]
    
    def has_successful_strategy(self) -> bool:
        return "SUCCESS" in self.strategy_results.values()
    
    def get_successful_strategies(self) -> List[str]:
        return [name for name, result in self.strategy_results.items() if result == "SUCCESS"]
    
    def __str__(self):
        return (f"AttackContext(target={self.target_url}, state={self.state}, "
                f"observations={len(self.observations)}, hypotheses={len(self.hypotheses)})")
    
    def __repr__(self):
        return str(self)
