"""
Configuration for mutex_signatures.py (analysis).
Copied from original config.py for modularization.
"""

MUTEX_CONFIG = {
    # Minimum length filter for extracted mutexes
    'min_mutex_length': 5,
    
    # Mutex creation API names to detect
    'mutex_apis': [
        "CreateMutexA",
        "CreateMutexW",
        "CreateMutexExA",
        "CreateMutexExW",
        "OpenMutexA",
        "OpenMutexW",
        "ReleaseMutex",
    ],
    
    # Regex patterns for extracting mutex names from strings
    'mutex_extraction_patterns': [
        r"Global\\[\w\-\{\}]+",
        r"Local\\[\w\-\{\}]+",
        r"Session\d+\\[\w\-\{\}]+",
    ],
    
    # Known malware mutex signatures organized by family
    'malware_signatures': {
        "Emotet": [
            r"Global\{[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}",
            r"Global\\OfficeUpdate",
        ],
        "TrickBot": [
            r"Global\{[a-f0-9]{32}\}",
            r"TrickBot",
        ],
        "Qakbot": [
            r"Global\\[A-F0-9]{16}",
            r"Qakbot_Mutex",
        ],
        "Mirai": [
            r"mirai",
            r"Mirai",
        ],
        "Zeus": [
            r"Global\\{[A-F0-9]{8}-[A-F0-9]{4}",
            r"Zeus",
        ],
        "Dridex": [
            r"Global\\Dridex",
            r"DridexMutex",
        ],
        "Locky": [
            r"Global\\Locky",
            r"lockymutex",
        ],
        "WannaCry": [
            r"WannaCry",
            r"Global\\WannaCry",
        ],
        "NotPetya": [
            r"Global\\NotPetya",
            r"NotPetya",
        ],
        "Cerber": [
            r"Global\\Cerber",
            r"CerberMutex",
        ],
        "GandCrab": [
            r"Global\\GandCrab",
            r"gandcrab",
        ],
    },
    
    # Generic suspicious mutex pattern types
    'suspicious_patterns': {
        "Random_Hex": r"Global\\[A-F0-9]{32,}",
        "Random_Mixed": r"Global\\[a-zA-Z0-9]{20,}",
        "UUID_Like": r"Global\\\{[A-F0-9]{8}-[A-F0-9]{4}",
        "Obfuscated": r"Global\\[a-zA-Z0-9]*[A-F0-9]{16}[a-zA-Z0-9]*",
    },
}
