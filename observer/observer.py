"""
Observer :
this is the c most critical components of the system
extract all possible intelligence from HTTP responses
reponse analysis:
-error messages
-tech stack detections
- WAF detection
- Filter behavior 
- Execution detection
- Content analysis
"""

import re
import sys
import os 
from typing import List, Dict , Optional , Any
from datetime import datetime


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.observation import Observation, ObservationType, confidenceLevel
from models.tech_stack import TechStack
from models.waf_profile import WAFProfile
from observer.fingerprinter import Fingerprinter
from observer.pattern_matcher import PatternMatcher

class Observer:
    def __init__(self):
        self.fingerprinter = Fingerprinter()
        self.pattern_matcher = PatternMatcher()


        #Track analysis hostory
        self.response_analyzed = 0 
        self.observation_created = 0

    def analyzed_response(self, response, context=None , payload_info: Dict[str, Any]= None) ->List[Observation]:
        observations = []
        payload_info = payload_info or {}

        self.response_analyzed += 1 

        #Analyzed uplaod result (success/failure ..)
        observations.extend(self._analyze_upload_result(response, payload_info))

        #Analyzed error messages
        observations.extend(self._analyze_error_messages(response))
        
        #detect blocking behavior 
        if context and context.baseline_response:
            observations.extend(self._analyze_blocking_behavior(
                context.baseline_response,
                response
            ))

        # detect tech stack 
        observations.extend(self._detect_tech_stack(response, context))

        # detect WAF
        observations.extend(self._detect_waf(response, context))

        #Analyze execution
        if payload_info.get("phase") == "access":
            observations.extend(self._analyze_execution(response))

        # Exttract uplaod path/filename
        if payload_info.get("phase") == "upload":
            observations.extend(self._extract_upload_info(response, payload_info))


        # Content anaysis (length , timing....)
        observations.extend(self._analyze_content_characteristics(response, context))
        
        self.observations_created += len(observations)        

        return observations
    

    def _analyze_upload_result(self, response, payload_info: Dict) -> List[Observation]:
        """
        Determine if upload succeeded or failed and why
        
        Returns:
            List of observations about upload result
        """
        observations = []
        
        status_code = response.status_code
        body = response.text if hasattr(response, 'text') else str(response)
        
        # Success indicators
        if status_code in [200, 201]:
            # Check for success keywords
            success_patterns = [
                r'success',
                r'uploaded',
                r'file.*saved',
                r'complete',
            ]
            
            for pattern in success_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    observations.append(Observation(
                        type=ObservationType.UPLOAD_SUCCESS,
                        confidence=ConfidenceLevel.HIGH,
                        evidence=[
                            f"HTTP {status_code}",
                            f"Success keyword: {pattern}",
                            f"Filename: {payload_info.get('filename', 'unknown')}"
                        ]
                    ))
                    break
        
        # Redirect can indicate success
        elif status_code in [302, 303]:
            observations.append(Observation(
                type=ObservationType.UPLOAD_SUCCESS,
                confidence=ConfidenceLevel.MEDIUM,
                evidence=[
                    f"HTTP {status_code} (redirect)",
                    f"May indicate successful upload",
                    f"Location: {response.headers.get('Location', 'N/A')}"
                ]
            ))
        
        # Rejection indicators
        elif status_code in [403, 406, 415]:
            observations.append(Observation(
                type=ObservationType.UPLOAD_REJECTED,
                confidence=ConfidenceLevel.HIGH,
                evidence=[
                    f"HTTP {status_code}",
                    f"Rejection status code",
                    f"Filename: {payload_info.get('filename', 'unknown')}"
                ]
            ))
        
        return observations
    

    def _analyze_error_messages(self, response) -> List[Observation]:
        """
        Extract intelligence from error messages
        
        Returns:
            Observations about what errors reveal
        """
        observations = []
        
        body = response.text if hasattr(response, 'text') else str(response)
        
        # Use pattern matcher to find error types
        error_matches = self.pattern_matcher.match_errors(body)
        
        for error_type, confidence in error_matches:
            # Map error types to observation types
            obs_type_mapping = {
                "extension_blocked": ObservationType.EXTENSION_FORCED,
                "mime_type_rejected": ObservationType.FILTER_DETECTED,
                "size_limit": ObservationType.ERROR_MESSAGE_DETECTED,
                "upload_success": ObservationType.UPLOAD_SUCCESS,
            }
            
            obs_type = obs_type_mapping.get(error_type, ObservationType.ERROR_MESSAGE_DETECTED)
            
            # Convert confidence to ConfidenceLevel
            if confidence >= 0.8:
                conf_level = ConfidenceLevel.HIGH
            elif confidence >= 0.5:
                conf_level = ConfidenceLevel.MEDIUM
            else:
                conf_level = ConfidenceLevel.LOW
            
            observations.append(Observation(
                type=obs_type,
                confidence=conf_level,
                evidence=[
                    f"Error type: {error_type}",
                    f"Pattern confidence: {confidence:.2%}",
                    f"Error snippet: {body[:200]}..."
                ]
            ))
        
        return observations
    

    def _analyze_blocking_behavior(self, baseline_response, injected_response) -> List[Observation]:
        """
        Compare baseline vs injected to understand HOW filtering works
        
        Returns:
            Observations about filter behavior
        """
        observations = []
        
        # Use pattern matcher's analysis
        analysis = self.pattern_matcher.analyze_blocking_behavior(
            baseline_response,
            injected_response
        )
        
        if analysis["blocked"]:
            # Convert confidence to ConfidenceLevel
            if analysis["confidence"] >= 0.7:
                conf_level = ConfidenceLevel.HIGH
            elif analysis["confidence"] >= 0.4:
                conf_level = ConfidenceLevel.MEDIUM
            else:
                conf_level = ConfidenceLevel.LOW
            
            observations.append(Observation(
                type=ObservationType.FILTER_DETECTED,
                confidence=conf_level,
                evidence=[
                    f"Block type: {analysis['block_type']}",
                    *analysis["evidence"]
                ]
            ))
        
        return observations
    

    def _detect_tech_stack(self, response, context) -> List[Observation]:
        """
        Detect technology stack from response
        
        Returns:
            Observations about detected technologies
        """
        observations = []
        
        # Only fingerprint once (on first response) or if context doesn't have it
        if context and context.tech_stack:
            return observations  # Already detected
        
        # Fingerprint the response
        tech_stack = self.fingerprinter.fingerprint(response, context)
        
        # If we detected anything, create observation
        if tech_stack.confidence > 0.3:
            observations.append(Observation(
                type=ObservationType.TECH_STACK_DETECTED,
                confidence=ConfidenceLevel.HIGH if tech_stack.confidence > 0.7 else ConfidenceLevel.MEDIUM,
                evidence=[
                    f"Tech Stack: {tech_stack.get_summary()}",
                    f"Detection confidence: {tech_stack.confidence:.2%}",
                    *[f"Source: {source}" for source in tech_stack.detection_sources]
                ]
            ))
            
            # Store in context
            if context:
                context.tech_stack = tech_stack
        
        return observations
    

    def _detect_waf(self, response, context) -> List[Observation]:
        """
        Detect Web Application Firewall
        
        Returns:
            Observations about WAF presence
        """
        observations = []
        
        # Only detect once
        if context and context.waf_profile and context.waf_profile.detected:
            return observations
        
        headers = response.headers if hasattr(response, 'headers') else {}
        body = response.text if hasattr(response, 'text') else str(response)
        status_code = response.status_code
        
        # Use pattern matcher to detect WAF
        waf_matches = self.pattern_matcher.match_waf(headers, body, status_code)
        
        if waf_matches:
            waf_name, confidence, signatures = waf_matches[0]  # Take most confident match
            
            # Create WAF profile
            waf_profile = WAFProfile(
                detected=True,
                vendor=waf_name,
                confidence=confidence,
                signatures=signatures
            )
            
            # Convert confidence to ConfidenceLevel
            if confidence >= 0.8:
                conf_level = ConfidenceLevel.HIGH
            elif confidence >= 0.5:
                conf_level = ConfidenceLevel.MEDIUM
            else:
                conf_level = ConfidenceLevel.LOW
            
            observations.append(Observation(
                type=ObservationType.WAF_DETECTED,
                confidence=conf_level,
                evidence=[
                    f"WAF vendor: {waf_name}",
                    f"Detection confidence: {confidence:.2%}",
                    *[f"Signature: {sig}" for sig in signatures]
                ]
            ))
            
            # Store in context
            if context:
                context.waf_profile = waf_profile
        
        return observations
    

    def _analyze_execution(self, response) -> List[Observation]:
        """
        Check if uploaded code was executed or just displayed
        
        Returns:
            Observations about code execution
        """
        observations = []
        
        body = response.text if hasattr(response, 'text') else str(response)
        
        # Use pattern matcher to check execution
        executed, evidence, confidence = self.pattern_matcher.check_execution(body)
        
        if executed:
            # Convert confidence to ConfidenceLevel
            if confidence >= 0.8:
                conf_level = ConfidenceLevel.HIGH
            elif confidence >= 0.5:
                conf_level = ConfidenceLevel.MEDIUM
            else:
                conf_level = ConfidenceLevel.LOW
            
            observations.append(Observation(
                type=ObservationType.CODE_EXECUTION_DETECTED,
                confidence=conf_level,
                evidence=[
                    evidence,
                    f"Response length: {len(body)} bytes",
                    f"Response preview: {body[:100]}..."
                ]
            ))
        else:
            # Code NOT executed (source visible)
            observations.append(Observation(
                type=ObservationType.FILE_READ_CONFIRMED,  # File was read but not executed
                confidence=ConfidenceLevel.MEDIUM,
                evidence=[
                    evidence,
                    "Source code visible in response"
                ]
            ))
        
        return observations
    

    def _extract_upload_info(self, response, payload_info: Dict) -> List[Observation]:
        """
        Extract information about where/how file was uploaded
        
        Returns:
            Observations with upload path/filename info
        """
        observations = []
        
        body = response.text if hasattr(response, 'text') else str(response)
        headers = response.headers if hasattr(response, 'headers') else {}
        
        # Extract uploaded filename
        filename = self.pattern_matcher.extract_upload_path(body, headers)
        
        if filename:
            observations.append(Observation(
                type=ObservationType.UPLOAD_SUCCESS,
                confidence=ConfidenceLevel.HIGH,
                evidence=[
                    f"Uploaded as: {filename}",
                    f"Original filename: {payload_info.get('filename', 'unknown')}",
                    "Filename extracted from response"
                ]
            ))
        
        return observations
    

    def _analyze_content_characteristics(self, response, context) -> List[Observation]:
        """
        Analyze general response characteristics
        
        Returns:
            Observations about response properties
        """
        observations = []
        
        body = response.text if hasattr(response, 'text') else str(response)
        
        # Significant response length (might indicate file inclusion)
        if len(body) > 50000:  # Large response
            observations.append(Observation(
                type=ObservationType.STRUCTURAL_CHANGE,
                confidence=ConfidenceLevel.MEDIUM,
                evidence=[
                    f"Large response: {len(body)} bytes",
                    "May indicate file inclusion or data leak"
                ]
            ))

            # Empty or very small response (might indicate execution with no output)
        elif len(body) < 10:
            observations.append(Observation(
                type=ObservationType.STRUCTURAL_CHANGE,
                confidence=ConfidenceLevel.LOW,
                evidence=[
                    f"Minimal response: {len(body)} bytes",
                    "May indicate execution with no output"
                ]
            ))
        
        return observations
    

    def get_statistics(self) -> Dict[str, int]:
        """
        Get observer statistics
        
        Returns:
            Dict with analysis statistics
        """
        return {
            "responses_analyzed": self.responses_analyzed,
            "observations_created": self.observations_created,
            "avg_observations_per_response": (
                self.observations_created / self.responses_analyzed 
                if self.responses_analyzed > 0 else 0
            )
        }
    
    