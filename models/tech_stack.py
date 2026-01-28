"""
Tech Stack Model

Represents detected technology stack of the target.
Used for intelligent strategy selection.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, List


@dataclass
class TechStack:
    """
    Detected technology stack information
    
    Example:
        TechStack(
            web_server="Apache",
            server_version="2.4.41",
            language="PHP",
            language_version="7.4.3",
            framework="Laravel",
            os="Linux"
        )
    """
    
    web_server: Optional[str] = None
    server_version: Optional[str] = None
    language: Optional[str] = None
    language_version: Optional[str] = None
    framework: Optional[str] = None
    framework_version: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    confidence: float = 0.0
    detection_sources: List[str] = field(default_factory=list)
    raw_headers: Dict[str, str] = field(default_factory=dict)
    additional_info: Dict[str, str] = field(default_factory=dict)
    
    
    def __post_init__(self):
       
        self.confidence = max(0.0, min(1.0, self.confidence))
    
    def is_apache(self) -> bool:
      
        return self.web_server and "apache" in self.web_server.lower()
    
    def is_nginx(self) -> bool:
        """Check if web server is Nginx"""
        return self.web_server and "nginx" in self.web_server.lower()
    
    def is_iis(self) -> bool:
        """Check if web server is IIS"""
        return self.web_server and "iis" in self.web_server.lower()
    
    def is_php(self) -> bool:
        return self.language and "php" in self.language.lower()
    
    def is_php_below_8(self) -> bool:
        """Check if PHP version is below 8.0 (vulnerable to null byte)"""
        if not self.is_php() or not self.language_version:
            return False
        
        try:
            major = int(self.language_version.split('.')[0])
            return major < 8
        except (ValueError, IndexError):
            return False
    
    def is_linux(self) -> bool:
        """Check if OS is Linux"""
        return self.os and "linux" in self.os.lower()
    
    def is_windows(self) -> bool:
        """Check if OS is Windows"""
        return self.os and "windows" in self.os.lower()
    
    def get_summary(self) -> str:
        """Get human-readable summary of detected tech stack"""
        parts = []
        
        if self.web_server:
            parts.append(f"Server: {self.web_server}")
            if self.server_version:
                parts[-1] += f"/{self.server_version}"
        
        if self.language:
            parts.append(f"Language: {self.language}")
            if self.language_version:
                parts[-1] += f" {self.language_version}"
        
        if self.framework:
            parts.append(f"Framework: {self.framework}")
        
        if self.os:
            parts.append(f"OS: {self.os}")
        
        if not parts:
            return "Unknown"
        
        return ", ".join(parts)
    
    def __str__(self):
        return f"TechStack({self.get_summary()})"
    
    def __repr__(self):
        return (f"TechStack(server={self.web_server}, language={self.language}, "
                f"confidence={self.confidence:.2f})")