from typing import List, Optional 
from models.attack_state import AttackState
from models.observation import Observation, ObservationType
from models.filters import FilterProfile
from models.capabilities import CapabilityProfile





class AttackContext: 
    def __init__(self, target_url:str, parameter:str):
        self.target_url = target_url
        self.parameter = parameter

        self.state: AttackState = AttackState.TARGET_READY
        self.filters = FilterProfile()
        self.capabilities = CapabilityProfile()

        self.observations: List[Observation] = []
        self.strategy_history: List[str] = []
        self.hypotheses: Dict[str, Hypothesis] = field(default_factory=dict)
        self.tech_stack: Optional[TechStack] = None
        self.waf_profile: Optional[WAFProfile] = None
        self.baseline_response: Optional[Response] = None
        self.strategy_results: Dict[str, StrategyStatus] = field(default_factory=dict)
    def add_observation(self, observation: Observation):
        self.observations.append(observation)
        self._update_from_observation(observation)

    def _update_from_observation(self, obs: Observation):
        if obs.type == ObservationType.FILE_READ_CONFIRMED:
            self.capabilities.can_read_files = True
            self.state = AttackState.CONFIRMED_LFI

        elif obs.type == ObservationType.CODE_EXECUTION_DETECTED:
            self.capabilities.can_execute_code = True
            self.state = AttackState.CODE_EXECUTION

        elif obs.type == ObservationType.FILTER_DOT_BLOCKED:
            self.capabilities.dot_blocked = True
            self.state = AttackState.FILTER_DETECTED 

        elif obs.type == ObservationType.FILTER_SLASH_BLOCKED:
            self.filters.slash_blocked = True
            self.state = AttackState.FILTER_DETECTED

        elif obs.type == ObservationType.EXTENSION_FORCED:
            self.filters.extension_forced = True
            self.state = AttackState.FILTER_DETECTED


    def record_strategy(self, strategy_name: str):
        self.strategy_history.append(strategy_name)