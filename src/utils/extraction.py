"""
Shared Extraction Utilities

Centralized string and binary extraction functions used across all analysis modules.
Eliminates code duplication by providing single source of truth for data extraction.
"""

import re
from typing import List
import pefile
from config.extraction_config import STRING_EXTRACTION_SETTINGS




def extract_all_strings(pe: pefile.PE) -> List[str]:
    """
    Extract both ASCII and Unicode strings from PE file sections.
    
    Args:
        pe: pefile.PE object
        
    Returns:
        List[str]: Combined list of extracted strings
    """
    strings = []
    min_len = STRING_EXTRACTION_SETTINGS['section_min_length']
    
    if not hasattr(pe, "sections"):
        return strings
    
    for section in pe.sections:
        try:
            data = section.get_data()
            # ASCII strings (printable chars, min length from config)
            ascii_pattern = rb'[\x20-\x7E]{%d,}' % min_len
            for match in re.findall(ascii_pattern, data):
                try:
                    strings.append(match.decode('ascii', errors='ignore'))
                except:
                    pass
            
            # Unicode strings (wide chars, min length from config)
            unicode_pattern = rb'(?:[\x20-\x7E]\x00){%d,}' % min_len
            for match in re.findall(unicode_pattern, data):
                try:
                    strings.append(match.decode('utf-16-le', errors='ignore'))
                except:
                    pass
        except:
            continue
    
    # Remove duplicates while preserving order
    seen = set()
    unique_strings = []
    for s in strings:
        if s and s not in seen:
            seen.add(s)
            unique_strings.append(s)
    
    return unique_strings


def extract_all_binary_data(pe: pefile.PE) -> bytes:
    """
    Extract all binary data from PE file sections.
    
    Args:
        pe: pefile.PE object
        
    Returns:
        bytes: Combined binary data from all sections
    """
    binary_data = b''
    
    if not hasattr(pe, "sections"):
        return binary_data
    
    for section in pe.sections:
        try:
            binary_data += section.get_data()
        except:
            continue
    
    return binary_data

