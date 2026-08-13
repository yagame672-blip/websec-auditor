import os
import sys

# Add repository root directory to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from websec_auditor.webui import Handler

class handler(Handler):
    pass
