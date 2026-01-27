from enum import Enum, auto 




class AttackState(Enum):
    TARGET_READY = auto()
    BASIC_LFI_TEST =  auto()
    FILTER_DETECTED = auto()
    LOW_CONFIDENCE = auto()
    CONFIRMED_LFI = auto()
    ADVANCED_EXPLOITAION = auto()
    CODE_EXECUTION = auto()
    POST_EXPLOIT = auto()