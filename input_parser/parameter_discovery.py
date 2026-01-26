"""
This modulr analyzes parsedURL objects and automatically identifies 
potential LFI/RFI injection points with confidence scoring 
This is INTELLIGENCE , not just exploitation.
"""


from dataclasses import dataclass 
from typing import List
from input_parser.url_parser import ParsedURL, QueryParameter   



@dataclass 
class InjectionPoint:
    localation: str     #'query' or 'path'
    name: str           #parameter name or path segment
    originale_value: str 
    confidence: int     #0-100
    reason: List[str]   #usefull for reports


   #PARAMETER DISCOVERY ENGINE 


class ParameterDiscovery:
    """
    Converts parsed URL data into ranked injection points 
    """


    def discover(self, parsed_url: ParsedURL) -> List[InjectionPoint]:
        injection_points = []

        #Analyze query pararmeters 
        for param in parsed_url.query_params:
            confidence , reasons = self._analyze_query_param(param)

            if confidence > 0:
                injection_points.append(
                    InjectionPoint(
                        location="query",
                        name=param.name,
                        original_value=param.raw_value or "",
                        confidence=confidence,
                        reason=reasons
                    )
                )

        #Analyze path segments (path-based LFI )
        for segment in parsed_url.path_segments:
            confidence, reasons = self._analyze_path_segment(segment)

            if confidence > 0:
                injection_points.append(
                    InjectionPoint(
                        location="path",
                        name=segment,
                        original_value=segment,
                        confidence=confidence,
                        reason=reasons
                    )
                )

        #Sort by confidence descending
        injection_points.sort(key=lambda x: x.confidence, reverse=True)

        return injection_points



    #INTERNAL analysis helpers 

    def _analyze_query_param(self, param: QueryParameter):
        confidence = 0 
        reasons = []

        #empty parameter = very strong candidate
        if param.is_empty:
            confidence += 40
            reasons.append("Empty parameter")

        #path-like name or value
        if param.is_path_like:
            confidence += 35
            reasons.append("Path-like parameter")


        #File extensions hint
        if param.decoded_value and "." in param.decoded_value:
            confidence += 15
            reasons.append("File extension detected in parameter value")

        #Known risky keywords
        risky_keywords = ["file", "path", "page", "include", "view", "load", "template" ]
        if any(k in param.name.lower() for k in risky_keywords):
            confidence += 20
            reasons.append("Risky keyword in parameter name")

        # Cap confidence 
        confidence = min(confidence, 100)

        return confidence, reasons
    

    def _analyze_path_segment(self, segment: str):
        confidence = 0 
        reasons = []

        # PHP / template files in path 
        if segment.endswith((".php", ".jsp", ".asp", ".inc")):
            confidence += 40
            reasons.append("Executable or template file in path")

        # Numeric path segments often replaceable 
        if segment.isdigit():
            confidence += 20
            reasons.append("Numeric path segment")

        # Generic file name 
        if "." in segment: 
            confidence += 15 
            reasons.append("File-like path segment")


        confidence = min(confidence, 100)
        
        return confidence, reasons