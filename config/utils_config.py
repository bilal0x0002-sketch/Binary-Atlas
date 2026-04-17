"""
Configuration for utils.py - PE file validation and core utility settings
Copied from original config.py for modularization.
"""

# ==================== PE FILE VALIDATION CONFIGURATION ====================
PE_VALIDATION_CONFIG = {
    'min_file_size': 512,             # Minimum bytes for valid PE file
    'pe_magic_signature': b"MZ",      # DOS header magic signature
    
    # Valid PE machine types
    'valid_machine_types': [
        0x014c,                       # i386 (32-bit x86)
        0x8664,                       # amd64 (64-bit x86)
        0xaa64,                       # arm64 (ARM64)
        0x01c0,                       # arm (ARM)
    ],
}

# ==================== STRING EXTRACTION CONFIGURATION ====================
STRING_EXTRACTION_SETTINGS = {
    'ascii_min_length': 6,          # Minimum ASCII string length for extraction
    'unicode_min_length': 8,        # Minimum Unicode string length for extraction
    'section_min_length': 4,        # Minimum string length for section extraction (both ASCII and Unicode)
    'extract_ascii': True,          # Enable ASCII string extraction
    'extract_unicode': True,        # Enable Unicode string extraction
}

# ==================== WHITELIST CONFIGURATION ====================
# Known legitimate Windows DLLs and binaries - won't trigger warnings
SAFE_DLLS = {
    "KERNEL32.dll", "ntdll.dll", "USER32.dll", "ADVAPI32.dll",
    "SHELL32.dll", "ole32.dll", "OleAut32.dll", "comctl32.dll",
    "SHLWAPI.dll", "WININET.dll", "msvcrt.dll", "msvcp_win.dll",
    "api-ms-win-crt-runtime-l1-1-0.dll", "api-ms-win-core-file-l1-1-0.dll",
    "api-ms-win-core-libraryloader-l1-2-0.dll", "GDI32.dll", "RPCRT4.dll",
}

# Whitelisted system binaries - these should NOT be flagged as malware
SAFE_SYSTEM_BINARIES = {
    "explorer.exe",      # Windows File Explorer
    "svchost.exe",       # Windows Service Host
    "lsass.exe",         # Local Security Authority
    "csrss.exe",         # Client/Server Runtime Subsystem
    "services.exe",      # Windows Service Manager
    "systemd.exe",       # System process
    "conhost.exe",       # Console Window Host
    "rundll32.exe",      # DLL Runtime
    "cmd.exe",           # Command Prompt
    "powershell.exe",    # PowerShell
    "wscript.exe",       # Windows Script Host (legitimate if not modified)
    "cscript.exe",       # Console Script Host
}

# Safe system paths - binaries from these paths are likely legitimate
SAFE_SYSTEM_PATHS = {
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
}
