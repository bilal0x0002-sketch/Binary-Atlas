"""
Configuration for import_anomalies.py (analysis).
Copied from original config.py for modularization.
"""

IMPORT_ANOMALIES_CONFIG = {
    # Anomaly score thresholds for severity classification
    'score_thresholds': {
        'critical': 50,   # Score > 50 = CRITICAL
        'warning': 30,    # Score > 30 = WARNING
    },
    # Known suspicious imported functions
    'suspicious_functions': {
        "GetProcAddress": {"severity": "HIGH", "reason": "Dynamic API loading"},
        "GetModuleHandle": {"severity": "MEDIUM", "reason": "Runtime module resolution"},
        "LoadLibrary": {"severity": "HIGH", "reason": "Dynamic library loading"},
        "CreateRemoteThread": {"severity": "CRITICAL", "reason": "Process injection"},
        "VirtualAlloc": {"severity": "HIGH", "reason": "Memory allocation (possibly for shellcode)"},
        "WriteProcessMemory": {"severity": "CRITICAL", "reason": "Process memory manipulation"},
        "ShellExecute": {"severity": "HIGH", "reason": "Command execution"},
        "WinExec": {"severity": "HIGH", "reason": "Legacy command execution"},
        "CreateProcess": {"severity": "MEDIUM", "reason": "Child process spawning"},
        "SetWindowsHookEx": {"severity": "HIGH", "reason": "Hook injection"},
        "InternetOpen": {"severity": "MEDIUM", "reason": "Network communication"},
        "HttpOpenRequest": {"severity": "MEDIUM", "reason": "HTTP requests"},
        "RegOpenKeyEx": {"severity": "MEDIUM", "reason": "Registry manipulation"},
        "RegSetValueEx": {"severity": "HIGH", "reason": "Registry persistence"},
        "CreateFile": {"severity": "LOW", "reason": "File access (often suspicious in context)"},
        "DllMain": {"severity": "HIGH", "reason": "DLL entry point (suspicious if called)"},
    },
    # Known suspicious DLLs
    # NOTE: kernel32.dll, user32.dll, advapi32.dll are standard and imported by virtually all Windows binaries.
    # They are NOT marked as suspicious here; specific functions within them are flagged instead.
    'suspicious_dlls': {
        "ntdll.dll": {"severity": "HIGH", "reason": "Native API (often used to bypass hooks)"},
        "ws2_32.dll": {"severity": "MEDIUM", "reason": "Winsock (network API)"},
    },
}

IMPORT_ANOMALY_SCORES = {
    'forward_reference': 5,
    'missing_dll': 10,
    'invalid_export': 7,
    'circular_dependency': 3,
    'stub_export': 1,
    'missing_function': 15,
    'circular_import': 12,
    'multiple_missing': 20,
    'forwarded_circular': 10,
}
