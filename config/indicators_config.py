"""
Configuration for indicators.py - IOC extraction and keyword detection
Copied from original config.py for modularization.
"""

# ==================== REGEX PATTERNS FOR IOC EXTRACTION ====================
REGEX_PATTERNS = {
    'ip_address': r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
    'domain': r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b",
    'url': r'https?://[A-Za-z0-9._:/?#@%&=+\-]+',
    'mutex': r"(?:(?:Global|Local|Session)\\[A-Za-z0-9_\-\{\}]{4,30}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\})",
    'registry_key': r"HKEY_[A-Z_]+\\[A-Za-z0-9_\\\- ]+",
    'user_agent': r"(?:Mozilla|Chrome|Opera|Safari|Dalvik|curl|wget)[^\n]{10,80}",
}

# ==================== KEYWORD DETECTION ====================
# Weak keywords that require additional context to avoid false positives
WEAK_KEYWORDS = {
    'token': {
        'name': 'token',
        'requires_context': True,
        'context_indicators': ['adjusttoken', 'openprocesstoken', 'accesstoken', 'impersonate'],
        'reasoning': "token appears in exception handling (bad_alloc) - needs privilege API context"
    },
    'exec': {
        'name': 'exec',
        'requires_context': True,
        'context_indicators': ['cmd.exe', 'powershell', 'createprocess', 'winexec'],
        'reasoning': "exec is common in normal code - needs command execution context"
    },
    '/c': {
        'name': '/c',
        'requires_context': True,
        'context_indicators': ['cmd.exe', 'cmd /c', 'cmd /k', 'createprocess', 'shellexecute'],
        'reasoning': "cmd.exe flag alone meaningless - needs actual command execution"
    },
    '/k': {
        'name': '/k',
        'requires_context': True,
        'context_indicators': ['cmd.exe', 'cmd /c', 'cmd /k', 'createprocess', 'shellexecute'],
        'reasoning': "cmd.exe flag alone meaningless - needs actual command execution"
    },
}

ANTI_VM_KEYWORDS = [
    "vbox", "vmware", "sandbox", "wireshark", "analysis",
    "xen", "qemu", "ptrace"  # Removed "debug" - too common in normal code (symbols, exception handling)
]

SUSPICIOUS_KEYWORDS = [
    "connect", "socket", "GET", "POST", "User-Agent", "/gate", "/panel",
    "upload", "download", "telegram", "discord", "webhook", "token",
    "keylogger", "password", "stealer", "stage2", "beacon", "c2",
    "remote", "exec", "cmd.exe", "/c", "/k", "powershell"
]

CLOUD_IOC_KEYWORDS = [
    "pastebin", "github", "dropbox", "mega.nz", "telegram",
    "discord", "ipfs"
]

# ==================== COMMAND EXECUTION PATTERNS ====================
COMMAND_EXECUTION_PATTERNS = [
    ("cmd.exe", "/c"),  # Command execution with output suppression
    ("cmd.exe", "/k"),  # Command execution with interactive shell
    ("powershell", "-command"),  # PowerShell command execution
]

# ==================== URL RISK CATEGORIZATION ====================
URL_RISK_CATEGORIES = {
    'benign': {
        'vendors': [
            'microsoft.com', 'msdn.microsoft.com', 'support.microsoft.com',
            'schemas.microsoft.com', 'windows.microsoft.com', 'cdn.microsoft.com',
            'w3.org', 'www.w3.org',
            'github.com', 'githubusercontent.com',  # Code repos
            'npmjs.com', 'registry.npmjs.org',  # Package repos
            'pypi.org', 'files.pythonhosted.org',  # Python packages
        ],
        'description': 'Microsoft and W3C domains (legitimate infrastructure)',
    },
    'low': {
        'vendors': ['cdn.jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com'],
        'description': 'Known-good CDNs and package repositories',
    },
    'high': {
        'patterns': ['dns.txt', 'pastebin', 'pastebinraw', 'hastebin', 'herokuapp.com'],
        'description': 'Dynamic domains (DGA-like patterns) or suspicious hosting',
    },
}

# ==================== USER AGENT FILTERING ====================
USER_AGENT_FILTER = {
    'exclude_strings': ['operating system', 'unknown', 'default', 'system'],
    'description': 'Filter out generic OS strings and compilation artifacts from user agents',
    'only_report_real_ua': True,  # Only report strings that look like actual user-agents (Mozilla, Chrome, Safari, etc)
}

# ==================== INDICATORS EXTRACTION PARAMETERS ====================
INDICATORS_EXTRACTION = {
    # String extraction parameters
    'string_extraction_min_length': 6,         # Minimum string length for extraction
    'padding_chars': '%+-,*()[]{}$@#^&=',      # Special chars to detect padding
    'padding_ratio_threshold': 0.7,            # Max ratio of padding chars (70%)
    'meaningful_string_letter_count': 2,       # Min letters for meaningful string
    'base64_min_length': 24,                   # Minimum base64 candidate length
    'base64_printable_ratio': 0.60,            # Min printable ratio after decoding
    
    # Stack string detection parameters
    'stack_string_chunk_size': 32,             # Default chunk size for reversed strings
    'stack_string_printable_threshold': 10,    # Min printable chars in chunk
    'stack_string_section_chunk_size': 64,     # Chunk size for section-aware detection
    'stack_string_section_threshold': 12,      # Min printable chars for section detection
    'stack_string_max_results': 50,            # Max stack strings to return
    
    # IOC extraction limits
    'max_ip_results': 200,                     # Maximum IPs to extract
    'max_url_results': 200,                    # Maximum URLs to extract
    'max_domain_results': 200,                 # Maximum domains to extract
    
    # IP candidate filtering keywords
    'networking_keywords': ('http', 'https', '://', 'connect', 'socket', 'host', 'port', 'get ', 'post ', 'user-agent', ':'),
    'version_metadata_keywords': ('fileversion', 'productversion', 'noisrev', 'version', 'manifest'),
    
    # Base64 decoding - strong indicators of C2 (decoder looks for these in decoded text)
    'base64_strong_markers': ('http', '//', '/gate', '/panel', 'webhook', 'token', 'discord', 'telegram', 'pastebin'),
    
    # Critical executable strings (used in is_meaningful_string() to accept short cmd strings)
    'critical_short_strings': ['cmd.exe', '/c', '/k', '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', 'cmd', 'sh', 'ksh', 'bash'],
    
    # ASCII string prioritization (critical indicators shown first)
    'ascii_critical_priority': {'cmd.exe', 'powershell', 'cmd', '.exe', '/c', '/k', 'http', 'https', '@', '.com', '.net', '.org'},
    
    # Report truncation limits (for readability - can show first N items then "... and X more")
    'report_truncation_limits': {
        'mutexes_report': 10000,           # Max mutexes to show in full report (markdown) - SHOW ALL
        'stack_strings_report': 10000,     # Max stack strings in report - SHOW ALL
        'ascii_strings_report': 10000,     # Max ASCII strings in report - SHOW ALL
        'base64_report': 10,               # Max base64 candidates in report
        'console_provenance_detail': 5,    # Max provenance entries to show in console (IPs, URLs, domains)
        'console_mutexes': 10000,          # Max mutexes to show in console output - SHOW ALL
        'console_decoded_c2': 3,           # Max decoded C2 items to show in console
    },
}
