"""
Configuration for packer_detector.py - Packer and obfuscation detection
(Minimal configuration - risk scoring removed)
"""

# ==================== ENTROPY THRESHOLDS (CENTRALIZED) ====================
# Packer/encryption detection thresholds
ENTROPY_THRESHOLDS_DETECTION = {
    'high_entropy': 7.0,           # Likely encrypted/packed
    'moderate_entropy': 5.0,       # Possibly suspicious
    'low_entropy': 3.0,            # Normal
}

# ==================== PACKER SIGNATURES ====================
PACKER_SIGNATURES = {
    'UPX': [r'UPX\d', r'\.UPX\d'],
    'ASPack': [r'ASPack', r'\.ASP'],
    'PECompact': [r'PECompact', r'\.PEC'],
    'MPRESS': [r'MPRESS\d', r'\.MPRESS'],
    'PEtite': [r'PEtite\d', r'\.PTI'],
    'Themida': [r'Themida', r'\.Themida'],
    'VMProtect': [r'VMProtect', r'\.VM'],
    'Confuser': [r'Confuser', r'\.konfuse'],
    'ConfuserEx': [r'ConfuserEx', r'\.confuse'],
    'CodeVirtualizer': [r'CodeVirtualizer', r'\.cvmp'],
    'Yoda': [r'Yoda', r'\.yoda'],
}

# ==================== OBFUSCATION PATTERNS ====================
OBFUSCATION_PATTERNS = {
    'dynamic_imports': {
        'keywords': ['loadlibrarya', 'loadlibraryw', 'getprocaddress'],
        'confidence': 'medium'
    },
    'encryption': {
        'keywords': ['crypt', 'encrypt', 'decrypt', 'rc4', 'aes', 'des'],
        'confidence': 'medium'
    },
    'reflection': {
        'keywords': ['reflection', 'gettype', 'invoke', 'assembly'],
        'confidence': 'low'
    },
}

# ==================== PACKER DETECTION CONFIG ====================
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
    
    'entropy_text_section_threshold': 0.85,
    'entropy_section_min_size': 16,
    
    # Unpacking stub detection
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
    ],
    'unpacking_apis_threshold_high': 3,
    'unpacking_apis_threshold_low': 1,
    
    # Obfuscation techniques detection
    'obfuscation_techniques': {
        "dynamic_imports": ["LoadLibraryA", "LoadLibraryW", "GetProcAddress"],
        "encryption": ["CryptEncrypt", "CryptDecrypt", "RC4", "AES"],
        "reflection": ["System.Reflection", "GetType", "Invoke"],
    },
    'obfuscation_techniques_threshold': 2,
    
    # Relocation table anomalies
    'relocation_excessive_threshold': 1500,
    'relocation_high_threshold': 500,
    
    # Code cave detection
    'code_cave_min_size': 128,
    'code_cave_null_byte_ratio': 0.9,
    
    # Section anomalies
    'section_suspicious_min_size': 1024,
    'section_compression_ratio_threshold': 2.0,
    'section_ratio_low_threshold': 0.5,
    
    # Virtual size checks
    'virtualsize_multiplier': 2,
    'virtualsize_unpacking_threshold': 7.0,
}
