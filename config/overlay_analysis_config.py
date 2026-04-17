"""
Configuration for overlay_analysis.py (analysis).
Copied from original config.py for modularization.
"""

OVERLAY_ANALYSIS_CONFIG = {
    # Entropy threshold for detecting encryption in overlay
    'entropy_encryption_threshold': 7.0,
    # ASCII readable text detection thresholds
    'readable_ascii_threshold': 800,
    'readable_ascii_sample_size': 1000,
    'readable_ascii_char_range': (32, 126),
}
