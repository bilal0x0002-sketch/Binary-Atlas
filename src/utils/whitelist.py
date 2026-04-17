"""
Whitelist and reputation checking for system binaries.
Reduces false positives by recognizing legitimate Windows files.
"""

import os
from typing import Optional, Dict

# Known good Windows executable signatures (MD5 hashes)
# These are from standard Windows installations
TRUSTED_SIGNATURES = {
    # Windows 10/11 explorer.exe (common versions)
    "a540d447132d1c883ffb81b4a63d7deb": "explorer.exe (Windows 10/11)",
    "e3f31c34e5137f0ecd4d6f5fcf81eaad": "explorer.exe (Windows 10)",
}

# Known system binaries - for informational context only
# These profiles help analysts understand findings but DO NOT suppress detections
SYSTEM_BINARY_PROFILES = {
    "explorer.exe": {
        "expected_risk_level": "INFO",
        "reason": "Windows File Explorer - system binary. May legitimately use APIs like GetProcAddress, VirtualAlloc, etc.",
    },
    "svchost.exe": {
        "expected_risk_level": "INFO",
        "reason": "Windows Service Host - system process. API usage is expected.",
    },
    "lsass.exe": {
        "expected_risk_level": "INFO",
        "reason": "Local Security Authority Subsystem - core Windows service.",
    },
    "cmd.exe": {
        "expected_risk_level": "INFO",
        "reason": "Windows Command Processor - legitimate shell.",
    },
    "powershell.exe": {
        "expected_risk_level": "INFO",
        "reason": "Windows PowerShell - legitimate scripting runtime.",
    },
}


def is_system_path(file_path: str) -> bool:
    """
    Check if a file is located in a known system path.
    
    Args:
        file_path: Path to check
        
    Returns:
        True if file is in a system directory, False otherwise
    """
    if not file_path:
        return False
        
    file_path_lower = file_path.lower()
    system_paths = [
        "c:\\windows\\system32",
        "c:\\windows\\syswow64",
        "c:\\windows",
        "c:\\program files",
    ]
    
    return any(file_path_lower.startswith(path) for path in system_paths)



def get_system_profile(file_name: str) -> Optional[Dict]:
    """
    Get the system binary profile if this is a known Windows binary.
    
    Args:
        file_name: Name of the executable
        
    Returns:
        Profile dictionary or None
    """
    for name, profile in SYSTEM_BINARY_PROFILES.items():
        if name.lower() == file_name.lower():
            return profile
    return None


def get_whitelist_report_note(file_path: str) -> Optional[str]:
    """
    Get a note to add to the report if file is whitelisted.
    
    Args:
        file_path: Path to analyzed file
        
    Returns:
        Report note or None
    """
    file_name = os.path.basename(file_path).lower()
    profile = get_system_profile(file_name)
    
    if profile:
        return f"[INFO] {file_name} is a known system binary: {profile.get('reason')}"
    
    if is_system_path(file_path):
        return f"[INFO] File is located in a system directory ({file_path})"
    
    return None
