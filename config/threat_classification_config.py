"""
Unified Threat Classification Configuration

Combines behavioral analysis, pattern matching, and indicator detection rules.
Used by threat_classifier.py to analyze PE files for malware indicators.
"""

# ==================== BEHAVIOR ANALYSIS CONFIGURATION ====================
BEHAVIOR_CONFIG = {
    # C2 and command execution keywords threshold
    'c2_keywords': ["connect", "socket", "c2", "exec", "token"],
    'c2_keywords_threshold': 2,  # Minimum keywords to trigger C2 correlation
    
    # Severity ordering for result sorting (lower number = higher priority)
    'severity_order': {"HIGH": 0, "MEDIUM": 1, "LOW": 2},
    
    # API behavior mapping: DLL -> {API -> (Behavior, Severity)}
    'behavior_map': {
        # KERNEL32.DLL - Core Windows APIs
        "KERNEL32.DLL": {
            # Code injection
            "VirtualAlloc": ("Code Injection", "HIGH"),
            "VirtualAllocEx": ("Code Injection", "HIGH"),
            "VirtualProtect": ("Code Injection", "HIGH"),
            "WriteProcessMemory": ("Code Injection", "HIGH"),
            "CreateRemoteThread": ("Code Injection", "HIGH"),
            "QueueUserAPC": ("Code Injection", "HIGH"),

            # Process execution
            "CreateProcessA": ("Process Execution", "MEDIUM"),
            "CreateProcessW": ("Process Execution", "MEDIUM"),
            "WinExec": ("Process Execution", "MEDIUM"),

            # Reconnaissance
            "GetSystemInfo": ("Reconnaissance", "LOW"),
            "GetComputerNameA": ("Reconnaissance", "LOW"),
            "GetComputerNameW": ("Reconnaissance", "LOW"),
            "GetUserNameA": ("Reconnaissance", "LOW"),
            "GetUserNameW": ("Reconnaissance", "LOW"),
            "GetAdaptersInfo": ("Reconnaissance", "LOW"),

            # File actions
            "CreateFileA": ("File Operations", "LOW"),
            "CreateFileW": ("File Operations", "LOW"),
            "WriteFile": ("File Operations", "MEDIUM"),
            "DeleteFileA": ("File Deletion", "MEDIUM"),
            "DeleteFileW": ("File Deletion", "MEDIUM"),

            # Anti-debugging
            "IsDebuggerPresent": ("Anti-Analysis", "MEDIUM"),
            "CheckRemoteDebuggerPresent": ("Anti-Analysis", "MEDIUM"),
            "OutputDebugStringA": ("Anti-Analysis", "LOW"),
            "OutputDebugStringW": ("Anti-Analysis", "LOW"),
            "GetTickCount": ("Anti-Analysis", "LOW"),
        },

        # NTDLL.DLL - Native API calls
        "NTDLL.DLL": {
            "NtAllocateVirtualMemory": ("Code Injection", "HIGH"),
            "NtWriteVirtualMemory": ("Code Injection", "HIGH"),
            "ZwMapViewOfSection": ("Process Hollowing", "HIGH"),
            "NtCreateMutant": ("Synchronization/C2", "MEDIUM"),
            "NtOpenMutant": ("Synchronization/C2", "MEDIUM"),
            "NtDelayExecution": ("Anti-Analysis", "LOW"),
        },

        # USER32.DLL - User interface and input
        "USER32.DLL": {
            # Keylogging and surveillance
            "SetWindowsHookExA": ("Keylogging", "HIGH"),
            "SetWindowsHookExW": ("Keylogging", "HIGH"),
            "GetAsyncKeyState": ("Keylogging", "HIGH"),
            "GetForegroundWindow": ("Keylogging", "HIGH"),
            "GetWindowTextA": ("Surveillance", "MEDIUM"),
            "GetWindowTextW": ("Surveillance", "MEDIUM"),
            "GetKeyState": ("Keylogging", "MEDIUM"),

            # RAT window control and input injection
            "EnumWindows": ("RAT Activity", "MEDIUM"),
            "PostMessageA": ("RAT Activity", "MEDIUM"),
            "PostMessageW": ("RAT Activity", "MEDIUM"),
            "SendMessageA": ("RAT Activity", "MEDIUM"),
            "SendMessageW": ("RAT Activity", "MEDIUM"),
        },

        # ADVAPI32.DLL - Registry and security APIs
        "ADVAPI32.DLL": {
            # Registry persistence
            "RegSetValueA": ("Registry Persistence", "MEDIUM"),
            "RegSetValueW": ("Registry Persistence", "MEDIUM"),
            "RegCreateKeyA": ("Registry Persistence", "MEDIUM"),
            "RegCreateKeyW": ("Registry Persistence", "MEDIUM"),
            "RegDeleteKeyA": ("Registry Modification", "MEDIUM"),
            "RegDeleteKeyW": ("Registry Modification", "MEDIUM"),

            # Privilege escalation
            "OpenProcessToken": ("Privilege Escalation", "HIGH"),
            "AdjustTokenPrivileges": ("Privilege Escalation", "HIGH"),
            "ImpersonateLoggedOnUser": ("Privilege Escalation", "HIGH"),
        },

        # WS2_32.DLL - Network sockets
        "WS2_32.DLL": {
            "WSAStartup": ("Network Communication", "LOW"),
            "connect": ("Network Communication", "MEDIUM"),
            "send": ("Network Communication", "MEDIUM"),
            "recv": ("Network Communication", "MEDIUM"),
            "closesocket": ("Network Communication", "LOW"),
        },

        # CRYPT32.DLL - Cryptography
        "CRYPT32.DLL": {
            "CryptEncrypt": ("Cryptography", "MEDIUM"),
            "CryptDecrypt": ("Cryptography", "MEDIUM"),
            "CryptAcquireContextA": ("Cryptography", "LOW"),
            "CryptAcquireContextW": ("Cryptography", "LOW"),
            "CryptImportKey": ("Cryptography", "LOW"),
            "CryptHashData": ("Cryptography", "LOW"),
            "CryptCreateHash": ("Cryptography", "LOW"),
        },

        # WININET.DLL - Internet APIs
        "WININET.DLL": {
            "InternetOpenUrlA": ("Network Download", "MEDIUM"),
            "InternetOpenUrlW": ("Network Download", "MEDIUM"),
            "InternetReadFile": ("Network Download", "MEDIUM"),
            "HttpOpenRequestA": ("HTTP Communication", "MEDIUM"),
            "HttpOpenRequestW": ("HTTP Communication", "MEDIUM"),
            "HttpSendRequestA": ("HTTP Communication", "MEDIUM"),
            "HttpSendRequestW": ("HTTP Communication", "MEDIUM"),
        },

        # URLMON.DLL - URL download APIs
        "URLMON.DLL": {
            "URLDownloadToFileA": ("File Download", "HIGH"),
            "URLDownloadToFileW": ("File Download", "HIGH"),
        },

        # Global DLL (empty string) - Dynamic API loading
        "": {
            "LoadLibraryA": ("Dynamic API Loading", "HIGH"),
            "LoadLibraryW": ("Dynamic API Loading", "HIGH"),
            "GetProcAddress": ("Dynamic API Loading", "HIGH"),
        }
    }
}

# ============================================
# Task Scheduler / Delayed Execution Detection
# ============================================
TASK_SCHEDULER_APIS = {
    'Sleep': {'risk': 'MEDIUM', 'category': 'EVASION'},
    'SleepEx': {'risk': 'MEDIUM', 'category': 'EVASION'},
    'WaitForSingleObject': {'risk': 'MEDIUM', 'category': 'EVASION'},
    'SetTimer': {'risk': 'MEDIUM', 'category': 'EVASION'},
    'CreateWaitableTimer': {'risk': 'MEDIUM', 'category': 'EVASION'},
    'SetWaitableTimer': {'risk': 'MEDIUM', 'category': 'EVASION'},
    'timeSetEvent': {'risk': 'MEDIUM', 'category': 'EVASION'},
    'CreateTimerQueueTimer': {'risk': 'MEDIUM', 'category': 'EVASION'},
    'WaitForMultipleObjects': {'risk': 'MEDIUM', 'category': 'EVASION'},
}

TASK_SCHEDULER_STRINGS = [
    'schtasks', 'schtasks.exe', '/create', '/tn', '/tr', '/sc',
    'TaskScheduler', 'CreateTask', 'RegisterTask', 'ITaskScheduler',
    'SchRpcRegisterTask', 'ITaskFolder', 'ITaskDefinition'
]

STARTUP_REGISTRY_KEYS = [
    'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
    'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
]

# ==================== PATTERN MATCHING CONFIGURATION ====================
PATTERN_MATCHING_CONFIG = {
    # Malware pattern definitions with confidence scoring
    'malware_patterns': {
        'CODE_INJECTION': {
            'confidence_boost': 20,
            'required_functions': ['VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread'],
            'description': 'Process injection capability detected',
            'malware_families': ['Zeus', 'SpyEye', 'most modern malware'],
            'severity': 'CRITICAL',
        },
        'PERSISTENCE_VIA_REGISTRY': {
            'confidence_boost': 15,
            'required_functions': ['RegOpenKeyEx', 'RegSetValueEx'],
            'required_dlls': ['advapi32.dll'],
            'description': 'Registry-based persistence mechanism detected',
            'malware_families': ['Conficker', 'Stuxnet', 'most backdoors'],
            'severity': 'HIGH',
        },
        'REMOTE_CODE_EXECUTION': {
            'confidence_boost': 15,
            'required_functions': ['CreateProcess', 'InternetOpen'],
            'description': 'Remote code execution pattern (command execution + network)',
            'malware_families': ['Botnet', 'RAT', 'C2 agent'],
            'severity': 'HIGH',
        },
        'DYNAMIC_API_LOADING_ADVANCED': {
            'confidence_boost': 12,
            'required_functions': ['GetProcAddress', 'LoadLibrary'],
            'risk_indicators': ['high_entropy_strings', 'ntdll_dll_import'],
            'description': 'Advanced anti-analysis with dynamic API loading',
            'malware_families': ['Modern ransomware', 'APT tools', 'polymorphic malware'],
            'severity': 'HIGH',
        },
        'MEMORY_INJECTION': {
            'confidence_boost': 8,
            'required_functions': ['VirtualAlloc'],
            'description': 'Memory allocation for code injection or shellcode',
            'malware_families': ['Shellcode-based malware', 'Exploit payloads'],
            'severity': 'MEDIUM',
        },
        'NETWORK_COMMUNICATION': {
            'confidence_boost': 10,
            'required_functions': ['InternetOpen', 'HttpOpenRequest'],
            'description': 'Network communication capability',
            'malware_families': ['Botnet', 'Worm', 'RAT'],
            'severity': 'MEDIUM',
        },
        'HOOK_INJECTION': {
            'confidence_boost': 12,
            'required_functions': ['SetWindowsHookEx'],
            'description': 'Windows hook-based injection detected',
            'malware_families': ['Spyware', 'Rootkit', 'Backdoor'],
            'severity': 'HIGH',
        },
        'MULTI_STAGE_PAYLOAD': {
            'confidence_boost': 25,
            'risk_indicators': ['embedded_pe', 'high_overlay_entropy', 'encrypted_strings'],
            'description': 'Multi-stage payload detected (dropper/stage 1)',
            'malware_families': ['APT', 'Banker', 'Advanced malware'],
            'severity': 'CRITICAL',
        },
        'PRIVILEGE_ESCALATION_SEQUENCE': {
            'confidence_boost': 22,
            'required_functions': ['OpenProcessToken', 'AdjustTokenPrivileges'],
            'description': 'Privilege escalation attempt (enable SeDebugPrivilege or similar)',
            'malware_families': ['Rootkit', 'Backdoor', 'Advanced Trojan'],
            'severity': 'CRITICAL',
        },
        'KEYLOGGING_PATTERN': {
            'confidence_boost': 18,
            'required_functions': ['GetAsyncKeyState', 'GetForegroundWindow'],
            'description': 'Keylogging behavior detected (monitor keyboard + window focus)',
            'malware_families': ['Spyware', 'Info-stealer', 'RAT'],
            'severity': 'HIGH',
        },
        'CRYPTOGRAPHIC_C2': {
            'confidence_boost': 20,
            'required_functions': ['CryptAcquireContextW', 'CryptEncrypt'],
            'description': 'Encrypted C2 communication capability (crypto + network)',
            'malware_families': ['Botnet', 'Trojan', 'RAT', 'Backdoor'],
            'severity': 'CRITICAL',
        },
        'ANTI_DEBUGGING_SUITE': {
            'confidence_boost': 12,
            'required_functions': ['IsDebuggerPresent', 'OutputDebugStringW'],
            'description': 'Anti-debugging and anti-analysis techniques detected',
            'malware_families': ['Packed malware', 'Protected Trojan', 'Advanced malware'],
            'severity': 'HIGH',
        },
        'FILE_EXFILTRATION': {
            'confidence_boost': 16,
            'required_functions': ['CreateFileW', 'ReadFile', 'InternetOpenW'],
            'description': 'File reading and exfiltration to remote server',
            'malware_families': ['Trojan', 'Spyware', 'APT malware'],
            'severity': 'HIGH',
        },
    },
    
    # Pattern matching bonus points
    'dll_match_bonus': 3,
    'risk_indicator_bonus': 5,
    
    # Malware confidence thresholds for severity classification
    'confidence_thresholds': {
        'malware_detected': 70,
        'suspicious_pattern': 40,
    },
    
    # Overlay entropy threshold for indicator extraction
    'overlay_entropy_threshold': 7.0,
    
    # Display limits
    'max_patterns_display': 10,
}

PATTERN_CONFIDENCE_WEIGHTS = {
    'behavioral_pattern': 3,
    'additional_pattern': 5,
}

# ==================== INDICATOR DETECTION RULES ====================
# API combinations for pattern detection
INDICATOR_DETECTION_RULES = {
    'registry_operations': ['RegOpenKeyEx', 'RegSetValueEx', 'RegCreateKeyExW', 'RegSetValueExW'],
    'network_apis': ['InternetOpen', 'HttpOpenRequest', 'WSAStartup', 'socket', 'connect'],
    'process_creation': ['CreateProcess', 'CreateProcessW', 'ShellExecuteExW'],
    'privilege_escalation': ['OpenProcessToken', 'LookupPrivilegeValueW', 'AdjustTokenPrivileges'],
    'keylogging': ['GetAsyncKeyState', 'GetKeyState', 'GetForegroundWindow', 'GetWindowThreadProcessId', 'SetWindowsHookEx'],
    'crypto_apis': ['CryptAcquireContextW', 'CryptAcquireContextA', 'CryptCreateHash', 'CryptEncrypt', 'CryptDecrypt', 'CryptHashData'],
    'anti_debug': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'OutputDebugStringW', 'QueryPerformanceFrequency'],
    'memory_injection': ['VirtualAlloc', 'VirtualAllocEx', 'WriteProcessMemory', 'VirtualProtect'],
    'file_operations': ['CreateFileW', 'ReadFile', 'WriteFile', 'DeleteFileW'],
}
