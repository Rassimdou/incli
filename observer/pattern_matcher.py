"""
Matches response against known patterns in the knowledge base
"""


import re 
from typing import List, Dict, Optional , Tuple
import sys 
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from knowledge.signatures import(
    ERROR_PATTERNS,
    WAF_SIGNATURES,
    SERVER_SIGNATURES,
    LANGUAGE_SIGNATURES,
    FRAMEWORK_SIGNATURES,
    EXECUTION_INDICATORS,
    UPLOAD_PATH_PATTERNS,
    get_error_pattern_for_text,
    get_waf_for_response,
    detect_tech_from_headers
)


class PatternMatcher:
    """
    Intelligent pattern matching against known signatures
    """

    def __init__(self):
        self.error_patterns = ERROR_PATTERNS
        self.waf_signatures = WAF_SIGNATURES
        self.server_signatures = SERVER_SIGNATURES
        self.language_signatures = LANGUAGE_SIGNATURES
        self.framework_signatures = FRAMEWORK_SIGNATURES
        self.execution_indicators = EXECUTION_INDICATORS
        self.upload_path_patterns = UPLOAD_PATH_PATTERNS


    def match_errors(self, text: str) -> List[Tuple[str, float]]:
        matches = []
        text_lower = text.lower()


        for error_type , error_data in self.error_patterns.items():
            for pattern in error_data["patterns"]:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    confidence = error_data.get("confidence", 0.5)
                    matches.append((error_type, confidence))
                    break # dont match patterns for same type 

            return matches 
        
        def match_waf(self, headers: Dict[str, str], body:str , status_code:int):
             """
        Detect WAF from response characteristics
        
        Args:
            headers: Response headers
            body: Response body
            status_code: HTTP status code
            
        Returns:
            List of (waf_name, confidence, signatures_matched) tuples
        """
        matches = []
        
        for waf_name , waf_data in self.waf_signatures.items():
            signatures_matched = []
            score = 0
            max_score = 0 

            #check headers 
            max_score += 1
            for header_pattern in waf_data.get("header", []):
                for header_name , header_value in headers.items():
                    if re.search(header_pattern,f"{header_name}:{header_value}", re.IGNORECASE):
                         score += 1 
                         signatures_matched.append(f"Header: {header_pattern}")
                         break 
                    if score > 0: 
                        break


                # check status codes 
                max_score += 1 
                if status_code in waf_data.get("status_codes", []):
                    score += 1 
                    signatures_matched.append(f"Status code: {status_code}")

                max_score += 1 
                for pattern in waf_data.get("body_patterns", []):
                    if re.search(pattern, body, re.IGNORECASE):
                        score += 1 
                        signatures_matched.append(f"Body pattern: {pattern}")
                        break

                    # calculate confidence based on matches 
                    if score >= 2: #need at least 2 indicators 
                        confidence =(score/ max_score) * waf_data.get("confidence_boost", 0.8)
                        matches.append((waf_name , confidence, signatures_matched))


                # sort by confidence 
                matches.sort(key=lambda x: x[1], reverse=True)

                return matches 
            
            def detect_server(self, header: Dict[str, str]) -> Optional[Tuple[str, Optional[str], float]]:
                """
            Detect web server from headers
        
            Args:
                headers: Response headers
            
            Returns:
                (server_name, version, confidence) or None
            """
                server_header = header.get("Server", "")

                if not server_header: 
                    return None 
                
                for server_name, patterns in self.server_signatures.items():
                    for pattern in patterns:
                        match = re.search(pattern, server_header, re.IGNORECASE)
                        if match: 
                            version = match.group(1) if match.groups() else None 
                            return (server_name, version , 0.95)
                        

                return None 
            

            def detect_language(self, header: Dict[str, str], body: str) -> List[Tuple [str, Optional[str], float , str]]:
                """
                Detect programming language
        
                Args:
                    headers: Response headers
                    body: Response body

                Returns:
                    List of (language_name, version, confidence, detection_source) tuples
            """
                detections = []
                
                for lang_name, lang_data in self.language_signatures.items():
                    # check headers 
                    for pattern in lang_data.get("header", []):
                        for header_name , header_value in headers.items():
                            header_str = f"{header_name}: {header_value}"
                            match = re.search(pattern, header_str, re.IGNORECASE)
                            if match: 
                                version = match.group(1) if match.groups() else None 
                                detections.append((lang_name, version , 0.9, "header"))
                                break 


                        # Check body patterns
                        for pattern in lang_data.get("body", []):
                            if re.search(pattern, body, re.IGNORECASE):
                                detections.append((lang_name, None, 0.7, "body_pattern"))
                                break
                            
                    
                        #check error messages 
                        for pattern in lang_data.get("errors",[]):
                            if re.search(pattern, body , re.IGNORECASE):
                                detections.append(lang_name, None, 0.8, "error_message")
                                break 


                    return detections
                
                def detect_framework(self, headers: Dict[str, str ], body: str) -> List[Tuple[str, float]]:

                    detections = []

                for framework_name, patterns in self.framework_signatures.items():
                    for pattern in patterns:
                        # check both headers and body 
                        combined = f"{headers} {body}"
                        if re.search(pattern , combined , re.IGNORECASE):
                            detections.append((framework_name, 0.7))
                            break

                return detections
            
            def check_execution(self, body:str ) -> Tuple[bool, str, float]:
                """
                check if code was executed (vs displayed as text)
                Args:
                    body: Response body
            
                Returns:
                    (executed, evidence, confidence) tuple
                """
                #FIrst check if source code is visible (not executed)
                for pattern in self.execution_indicators["code_not_executed"]:
                    if re.search(pattern, body, re.IGNORECASE):
                        return (False, f"Source code visible: {pattern} ", 0.95)
                    

                # CHeck for linux file indicators 
                for pattern in self.execution_indicators["linux_files"]:
                    if re.search(pattern, body, re.IGNORECASE):
                        return (True, f"Linux file content detected: {pattern}", 0.9)
        
                # Check for Windows file indicators
                for pattern in self.execution_indicators["windows_files"]:
                    if re.search(pattern, body, re.IGNORECASE):
                        return (True, f"Windows file content detected: {pattern}", 0.9)
        
                # Check for custom execution markers
                for pattern in self.execution_indicators["php_execution"]:
                    if re.search(pattern, body, re.IGNORECASE):
                        return (True, f"Execution marker detected: {pattern}", 0.95)
                    

                #IF response is short and dosnt contain html/source , likely executed
                if len(body)< 10000 and "<html"not in body.lower() and "<php" not in body:
                    if body.strip(): # Not empty 
                        return (True, "non-HTML response with no source code visible")
                    
                return(False, "No execution indicators",0.5)
            
            def extract_uplaod_path(self, response_text: str , header:Dict[str, str]):
                """
                Extract uploaded file path from response
                
                Args:
                    response_text: Response body
                    headers: Response headers
                    
                Returns:
                    Extracted filename or None
                """
                #check location header first 
                if "Location" in headers: 
                    location = headers["Location"]
                    if "/" in location:
                        #Extract filename from path
                        parts = location.split("/")
                        if parts[-1]:
                            return parts[-1]
                        
                # Try patterns in response body
                for pattern in self.upload_path_patterns:
                    match = re.search(pattern, response_text, re.IGNORECASE)
                    if match:
                        path = match.group(1)
                        # Extract just the filename
                        if "/" in path:
                            return path.split("/")[-1]
                        return path 
                    
                # check for json response 
                try: 
                    import json 
                    data = json.loads(response_text)

                    # Common JSON keys for filenames
                    for key in ["filename", "file", "path", "url", "location"]:
                        if key in data:
                            value = data[key]
                            if "/" in value:
                                return value.split("/")[-1]
                            return value
                        
                except:
                    pass

                return None
            
            def analyze_blocking_behavior(self, baseline_response, injected_response):
                """
                Compare baseline vs injected to understand blocking behavior
                
                Args:
                    baseline_response: Response from safe upload
                    injected_response: Response from malicious upload
                    
                Returns:
                    Dict with analysis results
                """

                analysis = {
                    "blocked":False,
                    "block_type":None,
                    "evidence": [],
                    "confidence": 0.0
                }

                #Compare status codes 
                if baseline_response.status_code == 200 and injected_response.status_code in [403, 406, 500]:
                    analysis["blocked"] = True
                    analysis["block_type"] = "status_code_rejection"
                    analysis["evidence"].append(f"Status changed:{baseline_response.status_code} -> {injected_response.status_code}")

                # Compare response lengths
                baseline_len = len(baseline_response.text)
                injected_len = len(injected_response.text)

                if abs(baseline_len - injected_len) > (baseline_len * 0.5):
                    analysis["evidence"].append(f"Significant length change: {baseline_len} → {injected_len}")
                    analysis["confidence"] += 0.2


                # Check for error meesaages 
                error_matches = self.match_errors(injected_response.text)
                if error_matches:
                    analysis["blocked"] =True
                    analysis["block_type"] = "error_message"
                    for error_type, conf in error_matches: 
                        analysis["evidence"].append(f"Error detected: {error_type}")
                        analysis["confidence"] += conf *0.2

                # check for WAF
                waf_matches = self.match_waf(
                    injected_response.headers,
                    injected_response.text,
                    injected_response.status_code
                )
                if waf_matches:
                    analysis["blocked"] = True
                    analysis["block_type"] = "waf"
                    waf_name = waf_matches[0][0]
                    analysis["evidence"].append(f"WAF detected: {waf_name}")
                    analysis["confidence"] += 0.4
                
                # Cap confidence at 1.0
                analysis["confidence"] = min(1.0, analysis["confidence"])
                
                return analysis