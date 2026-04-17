# config/security_checks_config.py
"""
Configuration for security_checks.py - PE security validation
"""

# ==================== SECURITY CHECKS CONFIGURATION ====================
SECURITY_CHECKS_CONFIG = {
    # Timestamp validation
    'timestamp_year_2000_unix': 946684800,  # Unix timestamp for 2000-01-01 00:00:00 UTC
    
    # Alignment thresholds
    'min_section_alignment': 0x1000,        # Minimum valid section alignment
    'valid_file_alignments': [0x200, 0x1000],  # Standard file alignment values
    
    # DLL security characteristics flags
    'security_flags': {
        'ASLR': 0x0040,                     # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (Address Space Layout Randomization)
        'DEP_NX': 0x0100,                   # IMAGE_DLLCHARACTERISTICS_NX_COMPAT (Data Execution Prevention / NX)
        'CFG': 0x4000,                      # IMAGE_DLLCHARACTERISTICS_GUARD_CF (Control Flow Guard)
    },
    
    # PE format markers
    'pe_magic_signatures': {
        'embedded_pe': b"MZ",               # Embedded PE signature in overlay
        'debug_type_pdb': 2,                # Debug directory type for PDB
        'debug_signature': b"RSDS",         # PDB debug signature
    },
}
