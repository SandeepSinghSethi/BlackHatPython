#!/usr/bin/env python3

from cryptography.utils import CryptograpyDeprecationWarning
import warnings
warnings.filterwarnings("ignore",category=CryptograpyDeprecationWarning)
from scapy.all import *
import cv2
import collections
import zlib
import re
import os
import sys

if os.getcwd() != '/secstr1/lvmst/black-hat-python/BlackHatPython/chapter4':

if not 'pictures' in 
outdir = os.getcwd()
Response = collections.namedtuple('Response',['header','payload'])
