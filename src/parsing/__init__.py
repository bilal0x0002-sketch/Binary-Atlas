"""
PE Parsing Module

Handles parsing of PE (Portable Executable) file structures:
- Headers (DOS, File, Optional)
- Sections (.text, .data, .rsrc, etc.)
- Security characteristics (ASLR, DEP, CFG)
"""

from src.parsing.headers import analyze_headers
from src.parsing.sections import analyze_sections
from src.parsing.security_checks import perform_security_checks

__all__ = [
    "analyze_headers",
    "analyze_sections",
    "perform_security_checks",
]
