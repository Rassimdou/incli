from typing import Dict, List, Tuple, Any
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.observation import ObservationType


class HypothesisRules:
    """
    Rule-based system for generating and scoring hypotheses
    
    This encodes expert knowledge:
    - What observations suggest what hypotheses
    - What hypotheses suggest what strategies
    - Confidence adjustments based on evidence
    """
    
    # Observation → Hypothesis mapping
    OBSERVATION_TO_HYPOTHESIS: Dict[ObservationType, List[Tuple[str, float]]] = {
        # Extension filtering observations
        ObservationType.EXTENSION_FORCED: [
            ("blacklist_filter", 0.7),
            ("extension_validation_active", 0.9),
        ],
        
        # Upload success observations
        ObservationType.UPLOAD_SUCCESS: [
            ("upload_enabled", 0.95),
            ("filter_bypassed", 0.5),  # Maybe bypassed, maybe just allowed
        ],
        
        # Filter detection
        ObservationType.FILTER_DETECTED: [
            ("security_filter_active", 0.8),
            ("waf_maybe", 0.3),
        ],
        
        # WAF detection
        ObservationType.WAF_DETECTED: [
            ("waf_present", 0.95),
            ("bypass_required", 0.9),
        ],
        
        # Code execution
        ObservationType.CODE_EXECUTION_DETECTED: [
            ("code_execution_possible", 0.95),
            ("php_enabled", 0.8),
            ("vulnerable_server", 0.85),
        ],
        
        # Null byte success
        ObservationType.NULL_BYTE_SUCCESS: [
            ("null_byte_vulnerable", 0.95),
            ("php_below_8", 0.9),
            ("blacklist_filter", 0.85),
        ],
    }
    
    # Tech Stack → Hypothesis mapping
    TECH_STACK_RULES: Dict[str, Dict[str, Any]] = {
        "Apache": {
            "hypotheses": [
                ("htaccess_possible", 0.8),
                ("apache_server", 0.95),
            ],
            "strategies_boost": ["htaccess_upload"]
        },
        
        "PHP/7": {
            "hypotheses": [
                ("php_below_8", 0.95),
                ("null_byte_vulnerable", 0.9),
            ],
            "strategies_boost": ["null_byte"]
        },
        
        "PHP/8": {
            "hypotheses": [
                ("php_8_or_above", 0.95),
                ("null_byte_not_vulnerable", 0.9),
            ],
            "strategies_penalize": ["null_byte"]
        },
        
        "Nginx": {
            "hypotheses": [
                ("nginx_server", 0.95),
            ],
            "strategies_boost": ["double_extension"]
        },
        
        "IIS": {
            "hypotheses": [
                ("iis_server", 0.95),
                ("aspnet_maybe", 0.6),
            ],
            "strategies_boost": ["case_manipulation"]
        },
    }
    
    
    HYPOTHESIS_TO_STRATEGIES: Dict[str, List[Tuple[str, float]]] = {
        "blacklist_filter": [
            ("null_byte", 0.9),
            ("double_extension", 0.8),
            ("case_manipulation", 0.7),
        ],
        
        "whitelist_filter": [
            ("polyglot", 0.9),
            ("magic_bytes", 0.8),
            ("content_type_override", 0.7),
        ],
        
        "waf_present": [
            ("encoding_bypass", 0.8),
            ("fragmentation", 0.7),
            ("time_delay", 0.6),
        ],
        
        "php_below_8": [
            ("null_byte", 0.95),
        ],
        
        "apache_server": [
            ("htaccess_upload", 0.8),
            ("null_byte", 0.7),
        ],
        
        "nginx_server": [
            ("double_extension", 0.8),
            ("case_manipulation", 0.6),
        ],
    }
    
    
    HYPOTHESIS_CONFLICTS: Dict[str, List[str]] = {
        "blacklist_filter": ["whitelist_filter"],
        "whitelist_filter": ["blacklist_filter"],
        "php_below_8": ["php_8_or_above"],
        "php_8_or_above": ["php_below_8", "null_byte_vulnerable"],
        "null_byte_vulnerable": ["php_8_or_above"],
    }
    
    
    EVIDENCE_STRENGTH: Dict[str, float] = {
        "Server header": 0.9,
        "Error message": 0.8,
        "Response body": 0.6,
        "Status code": 0.5,
        "Timing analysis": 0.4,
    }
    
    def get_hypotheses_for_observation(self, obs_type: ObservationType) -> List[Tuple[str, float]]:
        """
        Get hypotheses that this observation suggests
        
        Args:
            obs_type: Type of observation
            
        Returns:
            List of (hypothesis_name, initial_confidence) tuples
        """
        return self.OBSERVATION_TO_HYPOTHESIS.get(obs_type, [])
    
    def get_hypotheses_for_tech_stack(self, server: str = None, language: str = None, 
                                     language_version: str = None) -> List[Tuple[str, float]]:
        """
        Get hypotheses based on detected tech stack
        
        Args:
            server: Web server (Apache, Nginx, IIS)
            language: Programming language (PHP, Java, etc.)
            language_version: Language version (7.4, 8.0, etc.)
            
        Returns:
            List of (hypothesis_name, confidence) tuples
        """
        hypotheses = []
        
        if server:
            for tech_pattern, rule_data in self.TECH_STACK_RULES.items():
                if tech_pattern in server:
                    hypotheses.extend(rule_data.get("hypotheses", []))
        

        if language and language_version:
            tech_key = f"{language}/{language_version.split('.')[0]}"  # e.g., "PHP/7"
            if tech_key in self.TECH_STACK_RULES:
                hypotheses.extend(self.TECH_STACK_RULES[tech_key].get("hypotheses", []))
        
        return hypotheses
    
    def get_strategies_for_hypothesis(self, hypothesis_name: str) -> List[Tuple[str, float]]:
        """
        Get strategies suggested by this hypothesis
        
        Args:
            hypothesis_name: Name of the hypothesis
            
        Returns:
            List of (strategy_name, confidence_boost) tuples
        """
        return self.HYPOTHESIS_TO_STRATEGIES.get(hypothesis_name, [])
    
    def get_conflicting_hypotheses(self, hypothesis_name: str) -> List[str]:
        """
        Get hypotheses that conflict with this one
        
        Args:
            hypothesis_name: Name of the hypothesis
            
        Returns:
            List of conflicting hypothesis names
        """
        return self.HYPOTHESIS_CONFLICTS.get(hypothesis_name, [])
    
    def adjust_confidence_for_evidence(self, base_confidence: float, 
                                      evidence_source: str) -> float:
        """
        Adjust confidence based on evidence source reliability
        
        Args:
            base_confidence: Base confidence score
            evidence_source: Where the evidence came from
            
        Returns:
            Adjusted confidence score
        """
        strength = self.EVIDENCE_STRENGTH.get(evidence_source, 0.5)
        return base_confidence * strength
    
    def get_strategy_boost_for_tech(self, tech_stack) -> Dict[str, float]:
        """
        Get strategy confidence boosts based on tech stack
        
        Args:
            tech_stack: TechStack object
            
        Returns:
            Dict of {strategy_name: confidence_boost}
        """
        boosts = {}
        
        if tech_stack.web_server:
            for tech_pattern, rule_data in self.TECH_STACK_RULES.items():
                if tech_pattern in tech_stack.web_server:
                    for strategy in rule_data.get("strategies_boost", []):
                        boosts[strategy] = boosts.get(strategy, 1.0) * 1.5
        
        if tech_stack.language and tech_stack.language_version:
            tech_key = f"{tech_stack.language}/{tech_stack.language_version.split('.')[0]}"
            if tech_key in self.TECH_STACK_RULES:
                rule_data = self.TECH_STACK_RULES[tech_key]
                for strategy in rule_data.get("strategies_boost", []):
                    boosts[strategy] = boosts.get(strategy, 1.0) * 1.5
                for strategy in rule_data.get("strategies_penalize", []):
                    boosts[strategy] = boosts.get(strategy, 1.0) * 0.2
        
        return boosts