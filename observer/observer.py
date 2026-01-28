


class Observer:
    """
    Extracts all possible observations
    """
    def __init__(self):
        self.fingerprinter = Fingerprinter()
        self.pattern_matcher = PatternMatcher()


    def analyze_response(self, response, context, payload_info = None) ->List[Obsercation]

        #Analysis methods (each returns observations)
        def _analyze_upload_result(self, response) -> List[Observation]
        def _analyze_error_messages(self, response) -> List[Observation]
        def _detect_blocking_behavior(self, response) -> List[Observation]
        def _compare_with_baseline(self, response, baseline) -> List[Observation]
        def _detect_tech_stack(self, response) -> List[Observation]
        def _detect_waf(self, response) -> List[Observation]
        def _analyze_execution(self, response) -> List[Observation]
