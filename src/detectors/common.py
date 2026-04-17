"""
Common utilities for analysis modules

Consolidates repeated patterns:
- String extraction with error handling
- Case-insensitive matching
- Risk score calculation
- Console output formatting
"""

from typing import List
import pefile
from src.utils.extraction import extract_all_strings


def safe_extract_strings(pe: pefile.PE) -> List[str]:
    """
    Safely extract all strings from PE file with error handling.
    
    Args:
        pe: pefile.PE object
        
    Returns:
        List of extracted strings (empty list if extraction fails)
    """
    try:
        return extract_all_strings(pe)
    except Exception:
        return []  # Continue with empty list if extraction fails




