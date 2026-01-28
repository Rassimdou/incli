from dataclasses import dataclass 


@dataclass 
class FilterProfile:
    dot_blocked: bool = False 
    slash_blocked: bool = False 
    extension_forced: bool = False 
    normalization_detected: bool = False 
    null_byte_removed: bool = False 



    def any_filter_detected(self) -> bool:
        return any(vars(self).values())