from dataclasses import dataclass 



@dataclass 
class CapabilityProfile: 
    can_read_files: bool = False
    can_include_php: bool = False 
    can_execute_code: bool = False
    can_write_files: bool = False
    