"""
Configuration for shellcode_detection.py (analysis).
Copied from original config.py for modularization.
"""

SHELLCODE_CONFIG = {
    # Sophistication level thresholds
    'sophistication_thresholds': {
        'advanced': 5,
        'intermediate': 3,
    },
    
    # Minimum detection count for sophistication classification
    'min_total_found_threshold': 3,
}

SHELLCODE_PATTERNS = {
    'call_pop_patterns': [
        b"\xe8\x00\x00\x00\x00",
    ],
    'call_pop_pop_patterns': [
        (b"\xe8\x00\x00\x00\x00\x58", "call $+5; pop rax"),
        (b"\xe8\x00\x00\x00\x00\x59", "call $+5; pop rcx"),
        (b"\xe8\x00\x00\x00\x00\x5a", "call $+5; pop rdx"),
    ],
    'nop_sled_patterns': [
        b"\x90" * 8,
        b"\xcc" * 8,
    ],
    'nop_sled_min_length': 8,
    'int3_sled_pattern': b"\xcc" * 6,
    'nop_sled_report_limit': 5,
    
    'api_resolution_apis': [
        'LoadLibraryA',
        'LoadLibraryW',
        'GetProcAddress',
        'WinExec',
        'CreateProcessA',
    ],
    'kernel_references': [
        'kernel32.dll',
        'ntdll.dll',
    ],
    'api_resolution_threshold_high': 3,
    'api_resolution_threshold_low': 1,
    
    'rop_indicators': [
        r"pop.*ret",
        r"mov.*esp",
        r"add.*rsp",
        r"xchg",
        r"lea.*",
    ],
    'rop_string_max_length': 50,
    
    'heap_spray_indicators': [
        'VirtualAlloc',
        'HeapAlloc',
        'malloc',
        'memset',
        'FillMemory',
        'RtlFillMemory',
    ],
    
    'suspicious_opcodes': [
        (b"\xff\x15", "Indirect call (IAT)"),
        (b"\xff\x25", "Indirect jump (IAT)"),
        (b"\x55\x89\xe5", "push rbp; mov rbp, rsp (function prologue)"),
        (b"\x83\xc4", "add rsp (stack adjustment)"),
    ],
    'suspicious_opcode_threshold': 3,
}

MEMORY_INJECTION_PATTERNS = {
    'injection_apis': {
        'virtual_memory': [
            'VirtualAllocEx',
            'VirtualAlloc',
            'VirtualProtectEx',
            'VirtualProtect',
        ],
        'process_manipulation': [
            'CreateRemoteThread',
            'CreateRemoteThreadEx',
            'WriteProcessMemory',
            'ReadProcessMemory',
        ],
        'thread_execution': [
            'CreateThread',
            'ResumeThread',
            'SuspendThread',
        ],
    }
}
