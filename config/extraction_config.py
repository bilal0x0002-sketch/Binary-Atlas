# config/extraction_config.py
"""
Configuration for extraction.py - String extraction settings
"""

# ==================== STRING EXTRACTION CONFIGURATION ====================
STRING_EXTRACTION_SETTINGS = {
    'ascii_min_length': 6,          # Minimum ASCII string length for extraction
    'unicode_min_length': 8,        # Minimum Unicode string length for extraction
    'section_min_length': 4,        # Minimum string length for section extraction (both ASCII and Unicode)
    'extract_ascii': True,          # Enable ASCII string extraction
    'extract_unicode': True,        # Enable Unicode string extraction
}
