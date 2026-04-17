"""
Configuration for logger.py (utils).
Copied from original config.py for modularization.
"""

# ==================== OUTPUT CONFIGURATION ====================
OUTPUT_WIDTH = 120  # Console output width
OUTPUT_TIMESTAMP_FORMAT = "%Y%m%d_%H%M%S"  # Filename timestamp format

# ==================== VERBOSE MODE ====================
VERBOSE_MODE = False  # Set via CLI --verbose flag

# ==================== LOGGING ====================
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR

LOGGING_CONFIG = {
    'default_logger_name': 'pe_analyzer',      # Default logger instance name
    'default_level': 'INFO',                   # Default logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    'suppress_verbose_libraries': {
        'pefile': 'WARNING',                   # Suppress verbose pefile logs
        'rich': 'WARNING',                     # Suppress verbose rich logs
    },
}
