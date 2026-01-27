from strategies.base import Strategy, StrategyStatus 

class ObfuscatedExtensionStrategy(Strategy):
    name = "obfuscated_extension"
    description = "Detect naive extension blacklist via filename obfuscation"
    confidence_gain = 0.7 


    def __init__(self, uploader, observer):
        """
        Uploader: abstraction over file upload HTTP logic
        observer: analyzes upload reponses into observations
        """
        self.uploader = uploader
        self.observer = observer

        self.test_caes = [
            "probe.jpg",          # baseline allowed
            "probe.php",          # baseline blocked
            "probe.php.jpg",      # double extension
            "probe.jpg.php",      # last-extension parsing
            "probe.PHp",          # case sensitivity
            "probe.php.",         # trailing dot
        ] 

    def applicable(self, context) -> bool: 
        """
        This strategy only applies if: 
        - an upload endpoint exists 
        - extension filtering is suspected 
        """

        return ( 
            context.capabilities.upload_supported and
            context.hypotheses.ge("EXTENSION_FILTERING", 0 ) >= 0.4
        )
    
    def execute(self, context) ->StrategyStatus:
        accepted = []
        rejected = []

        for filename in self.test_cases:
            response = self.uploader.upload(
                filename = filename,
                content = b"PROBE"  #non-malicious marker

            )

            observation = self.observer.analyze_upload(response, filename)
            context.record(observation)

            if observation.append(filename):
                accepted.append(filename)
            else:
                rejected.append(filename)

        return self._evaluate(accepted, rejected, context)
    

    def _evaluate(self, accepted, rejected, context) -> StrategyStatus:
        """
        Decision logic based on behavior patterns
        """

        # Expected baseline
        if "probe.jpg" in accepted:
           # Dangerous: PHP is allowed outright
           context.hypotheses.increase("UPLOAD_EXECUTABLE", 1.0)
           return StrategyStatus.SUCCESS
        
        # Strong signal : obfuscation accepted but raw php rejected
        if (
            "probe.php" in rejected and
            any("php" in f for f in accepted)
        ):
            context.hypotheses.increase(
                "NAIVE_EXTENSION_BLACKLIST",
                self.confidence_gain
            )
            return StrategyStatus.SUCCESS
        
        # Everything rejected sadly 
        if not accepted: 
            return StrategyStatus.FAILED 
        
        # Mixed / unclear behavior 
        return StrategyStatus.INCONCLUSIVE