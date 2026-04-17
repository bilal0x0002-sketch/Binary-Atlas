"""
Configuration for yara_scanner.py (analysis).
Copied from original config.py for modularization.
"""

import os

# YARA rules path
YARA_RULES_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'samples', 'yara_rules')

YARA_SCANNER_CONFIG = {
    'rule_extensions': ['.yar', '.yara'],
    'default_severity': 'UNKNOWN',
    'default_category': 'UNKNOWN',
    'severity_levels': {
        'critical': 'CRITICAL',
        'high': 'HIGH',
        'medium': 'MEDIUM',
        'low': 'LOW',
    },
    'high_severity_display_limit': 15,
}
