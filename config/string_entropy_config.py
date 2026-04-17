"""
Configuration for string_entropy.py (analysis).
Copied from original config.py for modularization.
"""

STRING_ENTROPY_CONFIG = {
    # Main entropy threshold for flagging suspicious strings
    'main_threshold': 6.5,
    
    # Classification thresholds for encrypted/obfuscated strings
    'critical_entropy_threshold': 7.5,
    'high_entropy_threshold': 7.0,
    
    # Confidence levels for different entropy ranges
    'confidence_levels': {
        'critical': 'CRITICAL',
        'high': 'HIGH',
    },
    
    # Minimum string length to analyze (skip very short strings)
    'min_string_length': 4,
}

STRING_ENTROPY_DISPLAY_CONFIG = {
    'min_string_length_check': 4,
    'top_encrypted_display_limit': 10,
    'encrypted_string_truncate_length': 80,
}
