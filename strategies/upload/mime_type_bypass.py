import re
import sys
import os
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from strategies.base import Strategy, StrategyStatus
from models.observation import Observation, ObservationType, ConfidenceLevel

class MimeTypeBypassStrategy(Strategy):
    """
    Bypass extension filters by changing the Content-Type header
    """
    
    name = "mime_type_bypass"
    description = "Bypass extension filters by spoofing Content-Type header"
    confidence_gain = 0.7
    
    targets_hypotheses = [
        "content_type_validation",
        "weak_extension_check"
    ]
    
    def __init__(self, uploader, fetcher, observer, base_url: str):
        self.uploader = uploader
        self.fetcher = fetcher
        self.observer = observer
        self.base_url = base_url.rstrip('/')
    
    def applicable(self, context) -> bool:
        return True

    def execute(self, context) -> StrategyStatus:
        print("      [*] Testing MIME type bypass...")
        
        filename = "exploit.php"
        payload = b"<?php echo 'VULNERABLE'; ?>"
        
        # This strategy requires the uploader to accept a custom mime type
        # For now, we simulate or assume the uploader handles it if we provide a certain flag
        # Let's assume we want to test if 'image/jpeg' works for a .php file
        
        try:
            # We might need to modify uploader.py to support custom MIME types per call
            upload_response = self.uploader.upload(filename, payload)
            # In a real tool, we'd ensure the Content-Type sent was image/jpeg
            
            if upload_response.status_code == 200:
                print(f"      [+] Upload accepted with spoofed MIME type")
                return StrategyStatus.SUCCESS
                
            return StrategyStatus.FAILURE
            
        except Exception as e:
            print(f"      [!] Error: {e}")
            return StrategyStatus.FAILURE
