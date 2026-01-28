"""
Signatures & Pattern Database
==============================

Knowledge base of known patterns for detection.
Used by Observer and PatternMatcher.
"""

from typing import Dict, List, Any



# ERROR MESSAGE PATTERNS


ERROR_PATTERNS: Dict[str, Dict[str, Any]] = {
    "extension_blocked": {
        "patterns": [
            r"invalid file type",
            r"file type not allowed",
            r"only.*allowed",
            r"extension.*not permitted",
            r"extension.*not supported",
            r"file extension.*invalid",
            r"unsupported file type",
            r"prohibited file type",
        ],
        "confidence": 0.9,
        "indicates": "Extension filtering active"
    },
    
    "mime_type_rejected": {
        "patterns": [
            r"invalid mime type",
            r"content-type.*not allowed",
            r"mime.*not supported",
            r"wrong content type",
        ],
        "confidence": 0.85,
        "indicates": "MIME type validation active"
    },
    
    "size_limit": {
        "patterns": [
            r"file too large",
            r"exceeds.*size limit",
            r"maximum file size",
            r"file.*too big",
        ],
        "confidence": 0.95,
        "indicates": "File size limit enforced"
    },
    
    "upload_success": {
        "patterns": [
            r"successfully uploaded",
            r"file uploaded",
            r"upload.*success",
            r"file.*saved",
            r"upload complete",
        ],
        "confidence": 0.9,
        "indicates": "Upload succeeded"
    },
}



# WAF SIGNATURES


WAF_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "ModSecurity": {
        "headers": ["X-ModSecurity", "X-OWASP-ModSecurity"],
        "status_codes": [406, 501],
        "body_patterns": [
            r"mod_security",
            r"ModSecurity",
            r"This request has been blocked",
            r"OWASP ModSecurity Core Rule Set",
            r"406 Not Acceptable",
        ],
        "bypass_techniques": ["encoding", "case_variation", "null_byte", "fragmentation"],
        "confidence_boost": 0.9
    },
    
    "Cloudflare": {
        "headers": ["CF-RAY", "CF-Cache-Status", "__cfduid", "cf-request-id"],
        "status_codes": [403, 1020, 1010],
        "body_patterns": [
            r"cloudflare",
            r"Attention Required",
            r"Error 1020",
            r"Ray ID",
            r"cf-ray",
        ],
        "bypass_techniques": ["origin_ip", "encoding", "fragmentation"],
        "confidence_boost": 0.95
    },
    
    "AWS WAF": {
        "headers": ["X-AMZ-CF-ID", "X-AMZ-ID", "X-Amzn-RequestId"],
        "status_codes": [403],
        "body_patterns": [
            r"AWS WAF",
            r"Access Denied",
            r"RequestId",
            r"X-Amz",
        ],
        "bypass_techniques": ["encoding", "case_variation"],
        "confidence_boost": 0.85
    },
    
    "Imperva": {
        "headers": ["X-Iinfo", "X-CDN", "Set-Cookie.*visid_incap"],
        "status_codes": [403],
        "body_patterns": [
            r"Incapsula",
            r"Imperva",
            r"Access Denied",
            r"incapsula",
        ],
        "bypass_techniques": ["encoding", "time_delay", "fragmentation"],
        "confidence_boost": 0.9
    },
    
    "Akamai": {
        "headers": ["X-Akamai-Request-ID", "Akamai-Origin-Hop"],
        "status_codes": [403],
        "body_patterns": [
            r"Akamai",
            r"Access Denied",
            r"Reference #",
        ],
        "bypass_techniques": ["origin_ip", "encoding"],
        "confidence_boost": 0.85
    },
    
    "F5 BIG-IP": {
        "headers": ["X-WA-Info", "BigIP", "X-Cnection"],
        "status_codes": [403],
        "body_patterns": [
            r"F5",
            r"BigIP",
            r"Access Denied",
            r"The requested URL was rejected",
        ],
        "bypass_techniques": ["encoding", "case_variation"],
        "confidence_boost": 0.8
    },
}



# TECH STACK SIGNATURES


SERVER_SIGNATURES: Dict[str, List[str]] = {
    "Apache": [
        r"Apache/([\d.]+)",
        r"Server: Apache",
    ],
    "Nginx": [
        r"nginx/([\d.]+)",
        r"Server: nginx",
    ],
    "IIS": [
        r"Microsoft-IIS/([\d.]+)",
        r"Server: Microsoft-IIS",
    ],
    "LiteSpeed": [
        r"LiteSpeed/([\d.]+)",
        r"Server: LiteSpeed",
    ],
}

LANGUAGE_SIGNATURES: Dict[str, Dict[str, List[str]]] = {
    "PHP": {
        "headers": [
            r"X-Powered-By: PHP/([\d.]+)",
            r"Set-Cookie: PHPSESSID=",
        ],
        "body": [
            r"<\?php",
            r"Fatal error.*PHP",
            r"Warning.*PHP",
            r"Parse error.*PHP",
        ],
        "errors": [
            r"PHP Warning",
            r"PHP Fatal error",
            r"PHP Parse error",
        ]
    },
    
    "Java": {
        "headers": [
            r"X-Powered-By: Servlet",
            r"Set-Cookie: JSESSIONID=",
        ],
        "body": [
            r"<%@",
            r"javax\.",
            r"java\.",
        ],
        "errors": [
            r"java\.lang\.",
            r"javax\.servlet\.",
        ]
    },
    
    "ASP.NET": {
        "headers": [
            r"X-AspNet-Version",
            r"X-Powered-By: ASP\.NET",
            r"Set-Cookie: ASP\.NET_SessionId=",
        ],
        "body": [
            r"<%@",
            r"__VIEWSTATE",
        ],
        "errors": [
            r"System\.Web\.",
            r"Microsoft\.AspNetCore\.",
        ]
    },
}

FRAMEWORK_SIGNATURES: Dict[str, List[str]] = {
    "Laravel": [
        r"laravel_session",
        r"Laravel",
        r"Illuminate\\",
    ],
    "Symfony": [
        r"Symfony",
        r"symfony/",
    ],
    "Spring": [
        r"Spring Framework",
        r"springframework",
    ],
    "Express": [
        r"Express",
        r"X-Powered-By: Express",
    ],
}



# FILE EXECUTION INDICATORS


EXECUTION_INDICATORS: Dict[str, List[str]] = {
    "linux_files": [
        r"root:x:0:0",          # /etc/passwd
        r"daemon:x:",           # /etc/passwd
        r"/bin/bash",           # /etc/passwd
        r"/bin/sh",             # /etc/passwd
        r"Linux version",       # /proc/version
        r"www-data:",           # /etc/passwd
    ],
    
    "windows_files": [
        r"\[boot loader\]",     # boot.ini
        r"Windows Registry",    # Windows registry
        r"Microsoft Windows",   # Windows version
        r"C:\\Windows",         # Windows paths
    ],
    
    "php_execution": [
        r"EXEC_OK",             # Custom marker
        r"EXECUTED",            # Custom marker
        # If <?php tags NOT present, likely executed
    ],
    
    "code_not_executed": [
        r"<\?php",              # PHP source visible
        r"<%@",                 # JSP source visible
        r"<\%",                 # ASP source visible
    ],
}


# ============================================================================
# UPLOAD PATH PATTERNS
# ============================================================================

UPLOAD_PATH_PATTERNS: List[str] = [
    r"/files/avatars/([^'\"\s<>]+)",
    r"/files/uploads/([^'\"\s<>]+)",
    r"/uploads/([^'\"\s<>]+)",
    r"/upload/([^'\"\s<>]+)",
    r"/static/uploads/([^'\"\s<>]+)",
    r"/media/([^'\"\s<>]+)",
    r"/assets/uploads/([^'\"\s<>]+)",
    r"/user/uploads/([^'\"\s<>]+)",
    r"/avatar/([^'\"\s<>]+)",
    r"/profile/([^'\"\s<>]+)",
    r'src="([^"]*uploads[^"]*)"',
    r'href="([^"]*uploads[^"]*)"',
]


# ============================================================================
# FILTER BEHAVIOR PATTERNS
# ============================================================================

FILTER_BEHAVIORS: Dict[str, Dict[str, Any]] = {
    "blacklist": {
        "indicators": [
            "Specific extension blocked",
            "Other extensions allowed",
            "Error mentions extension",
        ],
        "confidence": 0.8,
        "suggested_bypasses": ["null_byte", "double_extension", "case_manipulation"]
    },
    
    "whitelist": {
        "indicators": [
            "Only specific extensions allowed",
            "Strict rejection pattern",
            "No extension variation works",
        ],
        "confidence": 0.85,
        "suggested_bypasses": ["polyglot", "magic_bytes", "content_type_override"]
    },
    
    "mime_validation": {
        "indicators": [
            "Content-Type checked",
            "MIME type error",
        ],
        "confidence": 0.9,
        "suggested_bypasses": ["content_type_spoofing", "polyglot"]
    },
    
    "magic_byte_check": {
        "indicators": [
            "File header checked",
            "Invalid image",
            "Corrupted file",
        ],
        "confidence": 0.85,
        "suggested_bypasses": ["polyglot", "magic_bytes"]
    },
}



# HELPER FUNCTIONS


def get_error_pattern_for_text(text: str) -> List[str]:
    """
    Find which error patterns match the given text
    
    Args:
        text: Response body text
        
    Returns:
        List of matching error pattern names
    """
    import re
    
    matches = []
    text_lower = text.lower()
    
    for pattern_name, pattern_data in ERROR_PATTERNS.items():
        for pattern in pattern_data["patterns"]:
            if re.search(pattern, text_lower, re.IGNORECASE):
                matches.append(pattern_name)
                break
    
    return matches


def get_waf_for_response(headers: Dict[str, str], body: str, status_code: int) -> List[str]:
    """
    Detect which WAFs match the response
    
    Args:
        headers: Response headers
        body: Response body
        status_code: HTTP status code
        
    Returns:
        List of matching WAF names
    """
    import re
    
    matches = []
    
    for waf_name, waf_data in WAF_SIGNATURES.items():
        score = 0
        
        # Check headers
        for header_pattern in waf_data.get("headers", []):
            for header_name, header_value in headers.items():
                if re.search(header_pattern, f"{header_name}: {header_value}", re.IGNORECASE):
                    score += 1
                    break
        
        # Check status codes
        if status_code in waf_data.get("status_codes", []):
            score += 1
        
        # Check body patterns
        for pattern in waf_data.get("body_patterns", []):
            if re.search(pattern, body, re.IGNORECASE):
                score += 1
                break
        
        # If multiple indicators matched, this is the WAF
        if score >= 2:
            matches.append(waf_name)
    
    return matches


def detect_tech_from_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Detect technology stack from headers
    
    Args:
        headers: Response headers
        
    Returns:
        Dict with detected tech: {"server": "Apache", "language": "PHP", ...}
    """
    import re
    
    detected = {}
    
    # Detect server
    server_header = headers.get("Server", "")
    for server_name, patterns in SERVER_SIGNATURES.items():
        for pattern in patterns:
            match = re.search(pattern, server_header, re.IGNORECASE)
            if match:
                detected["server"] = server_name
                if match.groups():
                    detected["server_version"] = match.group(1)
                break
    
    # Detect language from headers
    for header_name, header_value in headers.items():
        header_str = f"{header_name}: {header_value}"
        
        for lang_name, lang_data in LANGUAGE_SIGNATURES.items():
            for pattern in lang_data.get("headers", []):
                match = re.search(pattern, header_str, re.IGNORECASE)
                if match:
                    detected["language"] = lang_name
                    if match.groups():
                        detected["language_version"] = match.group(1)
                    break
    
    return detected