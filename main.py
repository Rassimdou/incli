"""
usage : 
python3 main.py -u <payload_url> --cookie "session=XXX" 
"""

import argparse
import sys 
import os 
import requests 
import re 
from typing import Optional 


#add current directory to path 
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from http.fetcher import Fetcher 
from http.uplaoder import uploader 
from models.attack_context import AttackContext
from intelligence.director import IntellegenceDirector