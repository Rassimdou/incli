"""
Null byte Upload bypass strategy module.
Implements the Null Byte injection technique for bypassing extension filters during file uploads.
Technique: Upload filename.php%00.jpg
Result : Server strips %00.jpg, treats file as .php
"""


from strategies.base import Strategy , StrategyStatus
from models.observation import Observation, ObservationType, confidenceLevel
import re 
from typing import Optional 



class NullByteUploadStrategy(Strategy):
    name = "null_byte_upload"
    description = "Upload PHP file using null byte injection (filename.php%00.jpg)"
    confidence_gain = 0.9


    def __init__(self, uploader, fetcher, base_url:str):
        self.uploader = uploader
        self.fetcher = fetcher
        self.base_url = base_url.strip('/')


    def applicable(self, context):
        """
        This strategy is applicable if:
        - Upload endpoint exists
        - Extension filtering is suspected
        -JPG/PNG allowed
        """


        return True # always try this technique for uplaod endpoints
    
    def execute(self, context) -> StrategyStatus:
        """
        Execute null byte upload bypass strategy.
        
        Technique: Upload filename.php%00.jpg
        Result: Server strips %00.jpg, treats file as .php
        """

        
        return StrategyStatus.INCONCLUSIVE