"""
FingerPrinter 
Detect technology stack from HTTP reponses.
Build Techstack objects with confidence scores
"""


import re 
from typing import Dict , Optional, List, Tuple
import sys 
import os 

#Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.tech_stack import TechStack
from knowledge.signatures import (
    SERVER_SIGNATURES,
    LANGUAGE_SIGNATURES,
    FRAMEWORK_SIGNATURES,
    detect_tech_from_headers
)


class Fingerprinter:
    """
    Technology stack detection adn fingerprinting
    """

    def __init__(self):
        self.server_signatures = SERVER_SIGNATURES
        self.language_signatures = LANGUAGE_SIGNATURES
        self.framework_signatures = FRAMEWORK_SIGNATURES


    def fimgerprint(self, response, context= None) -> TechStack:
        """
        Main fingerprinting method
        
        Args:
            response: HTTP response object with headers, body, status_code
            context: Optional AttackContext for additional intelligence
            
        Returns:
            TechStack object with detected information
        """

        tech_stack = TechStack()
        detection_sources = []

        #Extract data from response 
        headers = response.headers if hasattr(response, 'headers') else {}
        body = response.text if hasattr(response, 'text') else str(response)

        # 1. Detect web server 
        server_info =self.detct_server(headers)
        if server_info:
            tech_stack.web_server = server_info[0]
            tech_stack.server_version = server_info[1]
            detection_sources.append(f"Server:{server_info[2]}")

        #2. Detect programming langauge
        lang_info = self._detect_language(headers, body)
        if lang_info:
            tech_stack.language = lang_info[0]
            tech_stack.language_version = lang_info[1]
            detection_sources.append(f"Language: {lang_info[2]}")

        #3. Detect framework 
        framework_info = self._detect_framework(headers, body)
        if framework_info:
            tech_stack.framework = framework_info[0]
            tech_stack.framework_version = framework_info[1]
            detection_sources.append(f"Framework: {framework_info[2]}")


        #4. Detect OS (from paths in errors, headers..)
        os_info = self._detect_os(headers , body)
        if os_info: 
            tech_stack.os = os_info[0]
            tech_stack.os_version = os_info[1]
            detection_sources.append(f"OS: {os_info[2]}")


        #Store raw headers for references 
        tech_stack.raw_headers = dict(headers)

        #Calculate overall confidence 
        tech_stack.confidence = self.calculate_confidence(tech_stack)

        #Store detection source
        tech_stack.detection_sources = detection_sources

        return tech_stack
    
    def _detect_server(self , headers: Dict[str , str]) -> Optional[Tuple[str, Optional[str], str]]:
        """
        Detect web server from headers
        
        Returns:
            (server_name, version, detection_method) or None
        """
        # Check Server header 
        server_header = headers.get("Server", headers.get("server", ""))

        if not server_header:
            return None
        
        for server_name , patterns in self.server_signatures.items():
            for pattern in patterns:
                match = re.search(pattern, server_header , re.IGNORECASE)
                if match:
                    version = None
                    if match.groups():
                        version = match.group(1)

                    return (server_name , version , "Server header")
                

            # if we have a server header but dont recognize ot , still report it
            if server_name: 
                return(server_header , None , "Server header (unknown)")
            
            return None
        
    def _detect_lanaguge(self , headers: Dict[str, str], body:str) -> Optional[Tuple[str, Optional[str], str]]:
            """
            Detect programming language
        
            Returns:
                (language_name, version, detection_method) or None
            """
            #Priority 1: headers
            for lang_name, lang_data in self.language_signatures.items():
                for pattern in lang_data.get("headers",[]):
                    for header_name, header_value in headers.items():
                        header_str = f"{header_name}: {header_value}"
                        match = re.search(pattern, header_str, re.IGNORECASE)
                        if match: 
                            version = None
                            if match.groups():
                                version = match.group(1)

                            return (lang_name, version, "HTTP header")
                        

            #PRiority 2: Error messsages 
            for lang_name, lang_data in self.language_signatures.items():
                for pattern in  lang_data.get("errrors", []):
                    match = re.search(pattern, body, re.IGNORECASE)
                    if match:
                        # try to extract version from error 
                        version_match = re.search(r'(\d+\.\d+\.\d+)', body)
                        version = version_match.group(1) if version_match else None
                        return(lang_name, version , "Error message")
                    

            # Priority 3: body patterns
            for lang_name, lang_data in self.language_signatures.items():
                for pattern in lang_data.get("body", []):
                    if re.search(pattern, body, re.IGNORECASE):
                        return (lang_name, None, "Response body pattern")
                    

            return None
        
    def _detect_framework(self, headers: Dict[str, str], body: str) -> Optional[Tuple[str, Optional[str], str]]:
            """
            Detect application framework
            
            Returns:
                (framework_name, version, detection_method) or None
            """
            combined_text = f"{headers} {body}"
            
            for framework_name, patterns in self.framework_signatures.items():
                for pattern in patterns:
                    match = re.search(pattern, combined_text, re.IGNORECASE)
                    if match:
                        # Try to extract version
                        version_match = re.search(rf'{framework_name}[/\s](\d+\.\d+)', combined_text, re.IGNORECASE)
                        version = version_match.group(1) if version_match else None
                        
                        # Determine where it was found
                        if pattern in str(headers):
                            method = "HTTP header"
                        else:
                            method = "Response body"
                        
                        return (framework_name, version, method)
            
            return None
        

    def _detect_os(self, headers: Dict[str, str], body: str) -> Optional[Tuple[str, Optional[str], str]]:
            """
            Detect operating system
            
            Returns:
                (os_name, version, detection_method) or None
            """
            # Linux indicators
            linux_patterns = [
                r'/usr/bin',
                r'/var/www',
                r'/etc/',
                r'/home/',
                r'Linux',
                r'Ubuntu',
                r'Debian',
                r'CentOS',
            ]
            
            # Windows indicators
            windows_patterns = [
                r'C:\\Windows',
                r'C:\\Program Files',
                r'\\WINDOWS\\',
                r'Microsoft-IIS',
                r'ASP\.NET',
            ]
            
            combined_text = f"{headers} {body}"
            
            # Check for Linux
            for pattern in linux_patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    # Try to extract version
                    version_match = re.search(r'(Ubuntu|Debian|CentOS|Linux)[\s/](\d+\.?\d*)', combined_text, re.IGNORECASE)
                    version = version_match.group(2) if version_match and version_match.groups() else None
                    return ("Linux", version, "Path/error analysis")
            
            # Check for Windows
            for pattern in windows_patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    # Try to extract Windows version
                    version_match = re.search(r'Windows\s+(NT\s+)?(\d+\.?\d*)', combined_text, re.IGNORECASE)
                    version = version_match.group(2) if version_match and version_match.groups() else None
                    return ("Windows", version, "Path/error analysis")
            
            return None
        
    def _calculate_confidence(self, tech_stack: TechStack) -> float:
            """
            Calculate overall confidence in tech stack detection
            
            Args:
                tech_stack: TechStack object to evaluate
                
            Returns:
                Confidence score 0.0 to 1.0
            """
            confidence = 0.0
            components = 0
            
            # Each detected component adds to confidence
            if tech_stack.web_server:
                confidence += 0.25
                components += 1
                if tech_stack.server_version:
                    confidence += 0.05
            
            if tech_stack.language:
                confidence += 0.30
                components += 1
                if tech_stack.language_version:
                    confidence += 0.10
            
            if tech_stack.framework:
                confidence += 0.15
                components += 1
            
            if tech_stack.os:
                confidence += 0.15
                components += 1
            
            # If we detected multiple components, boost confidence
            if components >= 3:
                confidence *= 1.1
            
            # Cap at 1.0
            confidence = min(1.0, confidence)
            
            return confidence
        
    def _calculate_confidence(self, tech_stack: TechStack) -> float:
            """
            Calculate overall confidence in tech stack detection
            
            Args:
                tech_stack: TechStack object to evaluate
                
            Returns:
                Confidence score 0.0 to 1.0
            """
            confidence = 0.0
            components = 0
            
            # Each detected component adds to confidence
            if tech_stack.web_server:
                confidence += 0.25
                components += 1
                if tech_stack.server_version:
                    confidence += 0.05
            
            if tech_stack.language:
                confidence += 0.30
                components += 1
                if tech_stack.language_version:
                    confidence += 0.10
            
            if tech_stack.framework:
                confidence += 0.15
                components += 1
            
            if tech_stack.os:
                confidence += 0.15
                components += 1
            
            # If we detected multiple components, boost confidence
            if components >= 3:
                confidence *= 1.1
            
            # Cap at 1.0
            confidence = min(1.0, confidence)
            
            return confidence
    
    def fingerprint_from_error(self, error_message: str) -> TechStack:
            """
            Extract tech stack info specifically from error messages
            Error messages often contain valuable version information
            
            Args:
                error_message: Error message text
                
            Returns:
                TechStack with extracted information
            """
            tech_stack = TechStack()
            
            # PHP errors
            if re.search(r'PHP', error_message, re.IGNORECASE):
                tech_stack.language = "PHP"
                version_match = re.search(r'PHP[/\s](\d+\.\d+\.\d+)', error_message, re.IGNORECASE)
                if version_match:
                    tech_stack.language_version = version_match.group(1)
                tech_stack.detection_sources.append("Error message")
            
            # Java errors
            elif re.search(r'java\.|javax\.', error_message, re.IGNORECASE):
                tech_stack.language = "Java"
                tech_stack.detection_sources.append("Error stacktrace")
            
            # Python errors
            elif re.search(r'Traceback.*File.*\.py', error_message, re.IGNORECASE | re.DOTALL):
                tech_stack.language = "Python"
                version_match = re.search(r'Python[/\s](\d+\.\d+)', error_message, re.IGNORECASE)
                if version_match:
                    tech_stack.language_version = version_match.group(1)
                tech_stack.detection_sources.append("Error traceback")
            
            # ASP.NET errors
            elif re.search(r'System\.Web|ASP\.NET', error_message, re.IGNORECASE):
                tech_stack.language = "ASP.NET"
                tech_stack.detection_sources.append("Error stacktrace")
            
            # Extract paths for OS detection
            if '/usr/' in error_message or '/var/' in error_message or '/etc/' in error_message:
                tech_stack.os = "Linux"
                tech_stack.detection_sources.append("File paths in error")
            elif 'C:\\' in error_message or 'C:/' in error_message:
                tech_stack.os = "Windows"
                tech_stack.detection_sources.append("File paths in error")
            
            tech_stack.confidence = self._calculate_confidence(tech_stack)
            
            return tech_stack
        
    def combine_fingerprints(self, fingerprints: List[TechStack]) -> TechStack:
            """
            Combine multiple fingerprinting results into one
            Takes the most confident detection for each component
            
            Args:
                fingerprints: List of TechStack objects to combine
                
            Returns:
                Combined TechStack with best information from all
            """
            combined = TechStack()
            
            for fp in fingerprints:
                # Take server if we don't have it or this one has version
                if fp.web_server:
                    if not combined.web_server or (fp.server_version and not combined.server_version):
                        combined.web_server = fp.web_server
                        combined.server_version = fp.server_version
                
                # Take language if we don't have it or this one has version
                if fp.language:
                    if not combined.language or (fp.language_version and not combined.language_version):
                        combined.language = fp.language
                        combined.language_version = fp.language_version
                
                # Take framework
                if fp.framework and not combined.framework:
                    combined.framework = fp.framework
                    combined.framework_version = fp.framework_version
                
                # Take OS
                if fp.os and not combined.os:
                    combined.os = fp.os
                    combined.os_version = fp.os_version
                
                # Combine detection sources
                combined.detection_sources.extend(fp.detection_sources)
            
            # Remove duplicates from detection sources
            combined.detection_sources = list(set(combined.detection_sources))
            
            # Recalculate confidence
            combined.confidence = self._calculate_confidence(combined)
            
            return combined
