"""
Configuration for dll_hijacking.py (analysis).
Copied from original config.py for modularization.
"""

DLL_HIJACKING_CONFIG = {
    # Safe DLLs that are unlikely to be hijacked (system DLLs)
    'safe_dlls': [
        'kernel32.dll',
        'ntdll.dll',
        'user32.dll',
        'advapi32.dll',
        'gdi32.dll',
        'shell32.dll',
        'ole32.dll',
        'oleaut32.dll',
        'shlwapi.dll',
        'comctl32.dll',
        'comdlg32.dll',
        'uxtheme.dll',
        'mscorlib.dll',
        'msvcrt.dll',
        'mscoree.dll',
        'clr.dll',
    ],
    
    # Windows API forwarding DLL patterns (safe, never hijacked)
    'api_forwarding_patterns': [
        'api-ms-win-',  # All api-ms-win-core-*, api-ms-win-crt-*, etc.
    ],
    
    # Suspicious DLLs - those commonly used in hijacking attacks
    'suspicious_dlls': [
        'gdiplus.dll',       # Removed comdlg32, comctl32, shlwapi, ole32 - too common
        'winmm.dll',
        'avrt.dll',
        'libjack.dll',
        'libjack64.dll',
        'riched20.dll',      # Removed riched32 - likely false positive
        'msftedit.dll',
        'dsound.dll',
        'msimg32.dll',
    ],
    
    # Maximum locations to display in results
    'location_display_limit': 10,
    # Regex patterns for suspicious DLL locations (in LoadLibrary function)
    'suspicious_locations_patterns': [
        r'Temp.*\.dll',
        r'AppData.*\.dll',
        r'Downloads.*\.dll',
        r'Documents.*\.dll',
        r'Desktop.*\.dll',
        r'ProgramData.*\.dll',
    ],
    # Regex patterns for suspicious DLL locations (in _check_suspicious_locations)
    'suspicious_path_patterns': [
        r'[Tt]emp.*\.dll',
        r'[Aa]pp[Dd]ata.*\.dll',
        r'[Dd]ownloads.*\.dll',
        r'[Dd]ocuments.*\.dll',
        r'[Dd]esktop.*\.dll',
        r'[Pp]rogram[Ff]iles.*[Pp]rogram[Ff]iles.*\.dll',
        r'[A-Z]:\\[a-zA-Z0-9]+\.dll$',
        r'ProgramData.*\.dll',
    ],
    # Regex patterns for relative path references
    'relative_path_patterns': [
        r'^\.\\\w+',
        r'^\.\.\\\w+',
        r'^[a-zA-Z0-9_-]+\\',
    ],
}
