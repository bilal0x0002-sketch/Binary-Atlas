"""
Configuration for sections.py (core).
Copied from original config.py for modularization.
"""

PACKER_DETECTION_CONFIG = {
    # Section flags for characteristic checks
    'section_flags': {
        'executable': 0x20000000,  # IMAGE_SCN_MEM_EXECUTE
        'writable': 0x80000000,    # IMAGE_SCN_MEM_WRITE
        'readable': 0x40000000,    # IMAGE_SCN_MEM_READ
    },
    
    # Entropy analysis thresholds
    'entropy_thresholds': {
        'high_entropy': 7.4,          # High entropy = likely packed/encrypted
        'medium_entropy': 7.0,        # Medium entropy = possibly packed
        'low_entropy': 6.5,           # Low entropy = normal
    },
    
    # Packing confidence thresholds (based on detection indicators count)
    'confidence_thresholds': {
        'highly_likely': 5,
        'probable': 3,
    },
    
    # Entropy analysis thresholds
    'entropy_text_section_threshold': 0.85,
    'entropy_section_min_size': 16,
    
    # Unpacking stub detection - common API patterns indicating unpacking/self-modifying code
    'unpacking_indicators': [
        "VirtualAlloc",
        "VirtualProtect",
        "CreateFileMapping",
        "MapViewOfFile",
        "UnmapViewOfFile",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "SetThreadContext",
        "ResumeThread",
        "memcpy",
        "memmove",
    ],
    'unpacking_apis_threshold_high': 3,
    'unpacking_apis_threshold_low': 1,
    
    # Obfuscation techniques detection
    'obfuscation_techniques': {
        "dynamic_imports": ["LoadLibraryA", "LoadLibraryW", "GetProcAddress"],
        "encryption": ["CryptEncrypt", "CryptDecrypt", "RC4", "AES", "DES", "MD5", "SHA"],
        "reflection": ["GetType", "Invoke", "MethodInfo", "Reflection"],
        "string_encryption": ["DecryptString", "DeobfuscateString", "UnscrambleString"],
        "control_flow": ["indirect call", "indirect jump", "call offset"],
    },
    'obfuscation_techniques_threshold': 3,
    
    # Relocation table anomalies
    'relocation_excessive_threshold': 1000,
    'relocation_high_threshold': 100,
    
    # Section characteristics anomalies
    'suspicious_section_names': [
        ".code", ".packed", ".zipped", ".UPX", ".data0", "stub"
    ],
    
    # Section size thresholds
    'section_suspicious_min_size': 1024,
    'section_compression_ratio_threshold': 5,
    'section_ratio_low_threshold': 0.5,
    
    # Virtual size multiplier for unpacking detection
    'virtualsize_multiplier': 2,
    'virtualsize_unpacking_threshold': 7.0,
    
    # Code cave detection
    'code_cave_min_size': 64,
    'code_cave_null_byte_ratio': 0.9,
}
