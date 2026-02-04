from typing import List, Optional
from dataclasses import dataclass
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from observer.observer import Observer
from intelligence.hypothesis_engine import HypothesisEngine
from intelligence.strategy_ranker import StrategyRanker
from models.ranked_strategy import RankedStrategy
from strategies.base import StrategyStatus


@dataclass
class ScanResult:
    """Result of an intelligent scan"""
    vulnerabilities_found: bool
    successful_strategy: Optional[str] = None
    secret_extracted: Optional[str] = None
    hypotheses_final: dict = None
    observations_count: int = 0
    strategies_tried: int = 0


class IntelligenceDirector:
    """
    Main orchestrator - coordinates all intelligence components
    
    Workflow:
    1. Establish baseline
    2. Initial reconnaissance
    3. Build hypotheses
    4. Rank strategies
    5. Execute intelligently
    6. Learn and adapt
    """
    
    def __init__(self, context, uploader, fetcher):
        """
        Initialize director
        
        Args:
            context: AttackContext object
            uploader: Uploader instance (your http/uploader.py)
            fetcher: Fetcher instance (your http/fetcher.py)
        """
        self.context = context
        self.uploader = uploader
        self.fetcher = fetcher
        
   
        self.observer = Observer()
        self.hypothesis_engine = HypothesisEngine()
        self.strategy_ranker = StrategyRanker()
        

        self.strategies = self._load_strategies()

        self.phase = "initialization"
        self.strategies_tried = 0
        
    def _load_strategies(self) -> List:
        """Load all available strategies dynamically"""
        strategies = []
        strategy_classes = [
            ("strategies.upload.null_byte_upload", "NullByteUploadStrategy"),
            ("strategies.upload.double_extension", "DoubleExtensionStrategy"),
            ("strategies.upload.mime_type_bypass", "MimeTypeBypassStrategy"),
            ("strategies.upload.magic_bytes", "MagicBytesStrategy"),
            ("strategies.upload.htaccess_upload", "HtaccessUploadStrategy"),
        ]
        
        for module_path, class_name in strategy_classes:
            try:
                module = __import__(module_path, fromlist=[class_name])
                strategy_class = getattr(module, class_name)
                strategies.append(strategy_class(
                    uploader=self.uploader,
                    fetcher=self.fetcher,
                    observer=self.observer,
                    base_url=self.context.target_url
                ))
            except (ImportError, AttributeError) as e:
                print(f"[!] Warning: Could not load {class_name}: {e}")
        
        return strategies
    
    def run_intelligent_scan(self) -> ScanResult:
        """
        Main intelligent scan workflow
        
        Returns:
            ScanResult with findings
        """
        print("\n" + "="*70)
        print("INTELLIGENT FILE UPLOAD VULNERABILITY SCANNER")
        print("SQLMap-level Intelligence")
        print("="*70)
        print()
        
        #Establish Baseline
        self.phase = "baseline"
        print("[Phase 1] Establishing baseline behavior...")
        self._establish_baseline()
        self._display_intelligence()

        self.phase = "reconnaissance"
        print("\n[Phase 2] Reconnaissance - testing basic uploads...")
        self._initial_reconnaissance()
        self._display_intelligence()
        
        self.phase = "attack"
        print("\n[Phase 3] Intelligent attack execution...")
        print("-"*70)
        
        result = self._intelligent_attack_loop()
        
        print("-"*70)
        
        return self._generate_scan_result(result)
    
    def _establish_baseline(self):
        """
        Phase 1: Upload a safe file to understand normal behavior
        """
        print("  [*] Uploading baseline file (test.jpg)...")
        
        try:
            response = self.uploader.upload("baseline.jpg", b"FAKE_JPEG_DATA")
            

            observations = self.observer.analyze_response(
                response,
                self.context,
                {"phase": "baseline", "filename": "baseline.jpg"}
            )
            

            self.context.baseline_response = response
            
   
            for obs in observations:
                self.context.add_observation(obs)
            
            print(f"  [+] Baseline established ({len(observations)} observations)")
            
            # Update hypotheses
            self.context.hypotheses = self.hypothesis_engine.analyze(self.context)
            
        except Exception as e:
            print(f"  [!] Baseline error: {e}")
    
    def _initial_reconnaissance(self):
        """
        Phase 2: Test basic uploads to gather intelligence
        """
        test_cases = [
            ("test.php", b"<?php echo 'TEST'; ?>", "PHP file"),
            ("test.jsp", b"<% out.println('TEST'); %>", "JSP file"),
        ]
        
        for filename, content, description in test_cases:
            print(f"  [*] Testing: {description} ({filename})...")
            
            try:
                response = self.uploader.upload(filename, content)
             
                observations = self.observer.analyze_response(
                    response,
                    self.context,
                    {"phase": "recon", "filename": filename, "description": description}
                )
                
               
                for obs in observations:
                    self.context.add_observation(obs)
                
                print(f"      Status: HTTP {response.status_code}")
                print(f"      Observations: {len(observations)}")
              
                self.hypothesis_engine.update(self.context, observations)
                
            except Exception as e:
                print(f"      Error: {e}")
        
        self.context.hypotheses = self.hypothesis_engine.analyze(self.context)
    
    def _intelligent_attack_loop(self) -> bool:
        """
        Phase 3: Adaptive attack loop
        
        Returns:
            True if vulnerability found, False otherwise
        """
        max_attempts = 5
        attempt = 0
        
        while attempt < max_attempts:
            attempt += 1
            

            next_strategy = self._get_next_strategy()
            
            if not next_strategy:
                print("\n[*] No more strategies to try")
                break
            

            print(f"\n[Attempt {attempt}] Strategy: {next_strategy.strategy.name}")
            print(f"           Confidence: {next_strategy.get_score_percentage()}")
            print(f"           Reasoning: {next_strategy.reasoning}")
            print()
            
            # Execute strategy
            result = self._execute_strategy(next_strategy.strategy)
        
            if result == StrategyStatus.SUCCESS:
                print(f"\n[+] VULNERABILITY CONFIRMED!")
                print(f"    Working technique: {next_strategy.strategy.name}")
                return True
            elif result == StrategyStatus.FAILURE:
                print(f"    Result: Failed")
            else:
                print(f"    Result: Inconclusive")
            
            # Check if we should continue
            if not self._should_continue():
                break
        
        return False
    
    def _get_next_strategy(self) -> Optional[RankedStrategy]:
        """
        Decide what strategy to try next
        
        Returns:
            RankedStrategy or None
        """
     
        self.context.hypotheses = self.hypothesis_engine.analyze(self.context)

        ranked = self.strategy_ranker.rank(self.strategies, self.context)
        
        for strategy in ranked:
            strategy_name = strategy.strategy.name
            
            
            if strategy_name not in self.context.strategy_results:
                return strategy
            
          
            if strategy.score > 0.9 and self.context.strategy_results[strategy_name] == StrategyStatus.FAILURE:
                print(f"    [*] Retrying {strategy_name} (new evidence suggests it might work)")
                return strategy
        
        return None
    
    def _execute_strategy(self, strategy) -> StrategyStatus:
        """
        Execute a strategy and learn from the result
        
        Args:
            strategy: Strategy to execute
            
        Returns:
            StrategyStatus (SUCCESS, FAILURE, INCONCLUSIVE)
        """
        self.strategies_tried += 1
        
        try:
            
            result = strategy.execute(self.context)
            
           
            self.context.strategy_results[strategy.name] = result
            
            # The strategy should have added observations to context
            # Update hypotheses based on new observations
            if self.context.observations:
                recent_observations = self.context.observations[-5:]  # Last 5
                self.hypothesis_engine.update(self.context, recent_observations)
            
            return result
            
        except Exception as e:
            print(f"    [!] Strategy execution error: {e}")
            self.context.strategy_results[strategy.name] = StrategyStatus.FAILURE
            return StrategyStatus.FAILURE
    
    def _should_continue(self) -> bool:
        """
        Decide if we should continue trying strategies
        
        Returns:
            True if should continue, False otherwise
        """
        
        ranked = self.strategy_ranker.rank(self.strategies, self.context)
        
        for strategy in ranked:
           
            if strategy.strategy.name not in self.context.strategy_results:
                if strategy.score >= 0.4:
                    return True
        
        return False
    
    def _display_intelligence(self):
        """
        Display current intelligence state
        """
        print()
        print("  Current Intelligence:")
        
        
        if self.context.tech_stack and self.context.tech_stack.confidence > 0:
            print(f"    Tech Stack: {self.context.tech_stack.get_summary()}")
        
        
        if self.context.waf_profile and self.context.waf_profile.detected:
            print(f"    WAF: {self.context.waf_profile.vendor} ({self.context.waf_profile.confidence:.0%})")
        
        
        if self.context.hypotheses:
            top_hyps = self.hypothesis_engine.get_top_hypotheses(self.context.hypotheses, 3)
            if top_hyps:
                print(f"    Top Hypotheses:")
                for hyp in top_hyps:
                    print(f"      - {hyp.name}: {hyp.confidence:.0%}")
        
        print()
    
    def _generate_scan_result(self, success: bool) -> ScanResult:
        """
        Generate final scan result
        
        Args:
            success: Whether vulnerability was found
            
        Returns:
            ScanResult object
        """
        result = ScanResult(
            vulnerabilities_found=success,
            hypotheses_final=dict(self.context.hypotheses),
            observations_count=len(self.context.observations),
            strategies_tried=self.strategies_tried
        )
        
       
        for strategy_name, status in self.context.strategy_results.items():
            if status == StrategyStatus.SUCCESS:
                result.successful_strategy = strategy_name
                break
        
        
        if hasattr(self.context, 'secret'):
            result.secret_extracted = self.context.secret
        
        return result
    
    def explain_intelligence(self) -> str:
        """
        Generate detailed intelligence report
        
        Returns:
            Multi-line intelligence report
        """
        lines = []
        lines.append("="*70)
        lines.append("INTELLIGENCE REPORT")
        lines.append("="*70)
        
        
        lines.append(f"\nObservations Collected: {len(self.context.observations)}")
        lines.append(f"Hypotheses Generated: {len(self.context.hypotheses)}")
        lines.append(f"Strategies Tried: {self.strategies_tried}")
        
       
        if self.context.tech_stack:
            lines.append(f"\nTech Stack:")
            lines.append(f"  {self.context.tech_stack.get_summary()}")
            lines.append(f"  Confidence: {self.context.tech_stack.confidence:.0%}")
        
        
        if self.context.waf_profile and self.context.waf_profile.detected:
            lines.append(f"\nWAF Detected:")
            lines.append(f"  Vendor: {self.context.waf_profile.vendor}")
            lines.append(f"  Confidence: {self.context.waf_profile.confidence:.0%}")
        
       
        if self.context.hypotheses:
            lines.append(f"\nTop Hypotheses:")
            top = self.hypothesis_engine.get_top_hypotheses(self.context.hypotheses, 5)
            for hyp in top:
                lines.append(f"  - {hyp.name}: {hyp.confidence:.0%}")
                if hyp.suggested_strategies:
                    lines.append(f"    Suggests: {', '.join(hyp.suggested_strategies[:3])}")
        
        
        if self.context.strategy_results:
            lines.append(f"\nStrategy Results:")
            for strategy_name, status in self.context.strategy_results.items():
                lines.append(f"  - {strategy_name}: {status}")
        
        return "\n".join(lines)