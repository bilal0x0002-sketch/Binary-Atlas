"""
Configuration for resource_analysis.py (analysis).
Copied from original config.py for modularization.
"""

RESOURCE_ANALYSIS_CONFIG = {
    # PE signature detection thresholds
    'pe_e_lfanew_max': 1024,
    'pe_resource_min_size': 256,
    'pe_entropy_threshold': 7.0,
    
    # PE header struct offsets and sizes
    'pe_header_min_buffer': 64,
    'pe_lfanew_offset': 0x3C,
    'pe_lfanew_size': 4,
    'pe_signature_size': 4,
    
    # Suspicious resource detection
    'resource_type_id_threshold': 16,
    'resource_size_threshold': 10000,
    'high_entropy_display_limit': 5,
    
    # Risk score display thresholds
    'risk_score_critical': 50,
    'risk_score_warning': 20,
}
