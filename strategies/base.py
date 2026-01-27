from abc import ABC  , abstractmethod 
from enum import Enum, auto



class StrategyStatus(Enum):
    SUCCESS = auto()
    FAILURE = auto()    
    INCONCLUSIVE = auto()


class Strategy(ABC):
    """
    Base class for all attack strategies
    """

    name = "abstract"
    description = ""
    confidence_gain = 0.0

    @abstractmethod
    def applicable(self, context) -> bool:
        """
        Decide whether this strategy makes sense
        given the current context
        """
        pass

    @abstractmethod
    def execute(self, context) -> StrategyStatus:
        """
        Execute the strategy against the target
        using the provided context
        """
        pass