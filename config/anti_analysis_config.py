"""
Configuration for anti_analysis.py (analysis).
Copied from original config.py for modularization.
"""

ANTI_ANALYSIS_CONFIG = {
    # Sophistication level thresholds
    'sophistication_thresholds': {
        'advanced': 5,                      # 5+ techniques = ADVANCED
        'intermediate': 3,                  # 3-4 techniques = INTERMEDIATE
        'basic': 1,                         # 1-2 techniques = BASIC
    },
    
    # Anti-debug API keywords (removed GetTickCount - too common in normal apps)
    'anti_debug_apis': [
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "OutputDebugStringA",
        "OutputDebugStringW",
        "QueryPerformanceCounter",    # Removed GetTickCount/GetTickCount64 - normal timing
        "NtQueryInformationProcess",
        "SetUnhandledExceptionFilter",
        "DbgBreakPoint",
    ],
    
    # VM/Hypervisor detection patterns
    'vm_indicators': [
        ("VMware", r"VMware|vmware|VMWARE"),
        ("VirtualBox", r"VirtualBox|virtualbox"),
        ("Hyper-V", r"Hyper-V|Hyper-v|hyper-v|HYPER-V"),
        ("QEMU", r"QEMU|qemu|Bochs|bochs"),
        ("Xen", r"Xen|xen|XEN"),
        ("Parallels", r"Parallels|parallels"),
    ],
    
    # VM detection opcodes (binary patterns)
    # Note: Removed CPUID detection - too common in normal apps
    'vm_detection_opcodes': {
        'sidt': [b'\x0f\x01\x04', b'\x0f\x01\x44'],  # SIDT instruction variants
        'cpuid': None,                                # CPUID removed - too common
    },
    
    # Anti-sandbox detection patterns
    'sandbox_indicators': [
        ("Cuckoo", r"Cuckoo|cuckoo|CUCKOO"),
        ("Sandboxie", r"Sandboxie|sandboxie|SandboxieRpcss"),
        ("Any.run", r"Any\.run|any\.run|Anyruns"),
        ("Joe Sandbox", r"Joe|joe|JOE"),
        ("VMRay", r"VMRay|vmray"),
        ("Falcon Sandbox", r"Falcon|falcon"),
        ("Hybrid Analysis", r"Hybrid|hybrid"),
        ("Generic Sandbox", r"sandbox|Sandbox|SANDBOX"),
    ],
    
    # Anti-emulation detection patterns
    'emulation_indicators': [
        ("Bochs", r"Bochs|bochs"),
        ("QEMU", r"QEMU|qemu"),
        ("WineHQ", r"Wine|wine|WINE"),
        ("Dynamorio", r"Dynamorio|dynamorio"),
        ("PIN", r"^PIN$|pin.exe"),
        ("Frida", r"Frida|frida"),
        ("AppHP", r"AppHP"),
    ],
    
    # Timing-based anti-analysis checks
    'timing_indicators': [
        "GetTickCount",
        "GetTickCount64",
        "QueryPerformanceCounter",
        "QueryPerformanceFrequency",
        "GetLocalTime",
        "GetSystemTime",
    ],
    
    # Kernel-level debugging detection APIs
    'kernel_debugging_indicators': [
        "NtQuerySystemInformation",
        "NtSetInformationDebugObject",
        "NtQueryDebugFilterState",
        "NtSetDebugFilterState",
        "DbgBreakPoint",
        "DbgUiRemoteBreakin",
        "KD_DEBUGGER_ENABLED",
    ],
    
    # Token manipulation APIs for privilege escalation
    'token_manipulation_apis': [
        'OpenProcessToken',
        'OpenThreadToken',
        'GetTokenInformation',
        'SetTokenInformation',
        'AdjustTokenPrivileges',
        'AdjustTokenGroups',
        'DuplicateTokenEx',
        'ImpersonateLoggedOnUser',
        'RevertToSelf',
        'SetThreadToken',
        'GetLogicalDrives',
    ],
    
    # Dangerous privileges that indicate escalation attempts
    'dangerous_privileges': [
        'SeDebugPrivilege',
        'SeImpersonatePrivilege',
        'SeTcbPrivilege',
        'SeLoadDriverPrivilege',
        'SeAssignPrimaryTokenPrivilege',
        'SeTakeOwnershipPrivilege',
        'SeIncreaseQuotaPrivilege',
    ],
}

PRIVILEGE_TOKEN_PATTERNS = {
    'token_manipulation_apis': ANTI_ANALYSIS_CONFIG['token_manipulation_apis'],
    'dangerous_privileges': ANTI_ANALYSIS_CONFIG['dangerous_privileges'],
}