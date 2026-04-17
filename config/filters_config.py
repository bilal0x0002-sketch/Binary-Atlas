"""
Configuration for filters.py - String filtering and validation
Copied from original config.py for modularization.
"""

# ==================== FILTER CONFIGURATION ====================
# False positive reduction - domains that are benign despite looking suspicious
BENIGN_DOMAINS = {
    "gnu.sparse.offset",
    "schily.fflags",
    "schily.dev",
    "ustar",
    "octetstream",
    "iana",
    "www.w3.org",
    "schemas.microsoft.com",
    "msdn.microsoft.com",
    "support.microsoft.com",
}

# ==================== FILTERING & VALIDATION THRESHOLDS ====================
FILTER_THRESHOLDS = {
    # String filtering
    'string_min_length': 2,                    # Minimum string length for real_string filter
    'string_max_length': 300,                  # Maximum string length
    'string_min_letters_ratio': 0.40,          # Minimum letter proportion (40%)
    'string_min_alphanumeric_ratio': 0.30,     # Minimum alphanumeric proportion (30%)
    'string_max_special_ratio': 0.40,          # Maximum special character proportion (40%)
    'garbage_min_letters_ratio': 0.20,         # Minimum letters for garbage operand detection (20%)
    
    # Domain filtering
    'domain_min_length': 4,                    # Minimum domain length
    'domain_max_length': 253,                  # Maximum domain length (DNS limit)
    'domain_label_min_length': 4,              # Minimum length for meaningful domain label
    'domain_label_alpha_ratio': 0.60,          # Minimum alpha proportion in domain labels (60%)
    
    # Mutex filtering
    'mutex_min_length': 4,                     # Minimum mutex string length
    'mutex_max_length': 128,                   # Maximum mutex string length
    'mutex_max_consecutive_digits': 3,         # Reject mutexes with 3+ consecutive digits
    'mutex_max_digit_letter_alternation': 0.5, # Maximum digit-letter alternation ratio (50%)
    'mutex_min_case_transitions': 2,           # Minimum case transitions for CamelCase detection
    'mutex_min_alpha_chars': 3,                # Minimum alpha characters required
    
    # Base64 filtering
    'base64_min_length': 24,                   # Minimum base64 string length
    'base64_length_multiple': 4,               # Base64 must be multiple of this
    'base64_min_charset_variety': 6,           # Minimum unique characters in base64
}

# ==================== FILTER KEYWORD LISTS (TUNABLE) ====================
FILTER_KEYWORDS = {
    'bad_keywords': [
        # config/resource files
        '.dat', '.ifl', '.rtf', '.ini', '.cfg', '.xml', '.json', 'serials',
        'commands', 'languages', 'wizard', 'setup', 'install', 'registry',
        'variables', 'messages', 'default', 'startmenu', 'desktop',

        # locale/time
        'january', 'february', 'march', 'april', 'may', 'june', 'july', 'august',
        'september', 'october', 'november', 'december',
        'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday',
        'utc', 'gmt', 'est', 'pst',

        # languages / countries / cities (common locale noise)
        'london', 'tokyo', 'paris', 'berlin', 'spanish', 'french', 'german',
        'english', 'portuguese', 'italian', 'russian', 'chinese', 'japanese', 'korean',

        # windows API/library names (extended)
        'hkey_', 'clsid', 'kernel32', 'user32', 'advapi32', 'ntdll', 'shell32',
        'comctl32', 'ole32', 'mscoree', 'ole.', 'iat_', 'msimg32', 'oleaut32',
        'comdlg32', 'gdiplus', 'uxtheme', 'shlwapi', 'winspool', 'winmm',

        # format/assertion/formatting strings
        'assertion', 'failed!', 'expression:', 'program:', 'microsoft visual',
        'hmac-sha', 'md5digest', 'sha256', 'sha512', 'sha1',
    ],
    'encoding_labels': ['UTF-16', 'UTF-8', 'UNICODE', 'ASCII', 'ANSI', 'ISO-8859', 'UTF8', 'UTF16'],
    'english_words_to_reject': [
        'application', 'default', 'language', 'languages', 'january', 'february', 'march',
        'april', 'may', 'june', 'july', 'august', 'september', 'october', 'november', 'december',
        'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday',
        'english', 'french', 'german', 'spanish', 'portuguese', 'italian', 'russian', 'chinese', 'japanese',
        'kernel32', 'user32', 'advapi32', 'ntdll', 'shell32', 'ole32', 'comdlg32', 'comctl32',
        'getprocaddress', 'createfilesw', 'adjusttokenprivileges', 'loadlibrary',
        'architecture', 'version', 'company', 'product', 'copyright', 'filename',
        'comments', 'description', 'internal', 'original', 'private', 'productversion',
        'fileversion', 'information', 'resource', 'registry', 'setup', 'install', 'wizard',
        'license', 'agreement', 'folder', 'desktop', 'program', 'windows', 'system',
        'access', 'button', 'cancel', 'close', 'error', 'failed', 'invalid', 'unable',
        'channels', 'channel', 'audio', 'output', 'stream', 'buffer', 'memory', 'thread',
    ],
    'domain_false_positives': [
        # archive metadata / tar/iso markers
        'gnu.sparse', 'gnu.', 'schily.', 'libarchive', 'tar.', 'ustar', 'rockridge', 'rrip', 'joliet',
        'iso9660', 'warc',

        # module names and resource library noise
        'winspool', 'kernel32', 'user32', 'advapi32', 'ntdll', 'mscoree', 'shell32',
        'comctl32', 'ole32', 'oleaut32', 'msimg32', 'riched', 'msftedit', 'comdlg32',
        'gdiplus', 'uxtheme', 'shlwapi', 'winmm', 'ole', 'crypt', 'advapi',

        # placeholder / config markers
        'empty.', '.empty', '.format', '.config', '.data',

        # config file extensions (reject these entirely)
        '.dat', '.ifl', '.rtf', '.ini', '.cfg', '.xml', '.json',

        # common public domains and hosts (avoid treating them as C2 without further context)
        'localhost', 'example.', 'test.', 'internal.', 'local.', 'schemas.microsoft',

        # compressed/archive terms
        'zip', 'gzip', 'bzip', 'lzma', 'compress', '7zip', 'archive',

        # ignore some big public domains as flagged noise sources in repository outputs
        'github.com', 'google.com',
    ],
    'mutex_bad_keywords': [
        'padding', 'infinity', 'comspec', 'tpooo', 'ngpadding',
        'channel_aux', 'channel_back', 'channel_front', 'channel_side', 'channel_top',
        'channel_mono', 'channel_none', 'channel_lfe',
        'advapi', 'comctl',
        'abcdefgh', 'zyxwvut',
        'abstract', 'alignment', 'arithmetic', 'attribute',
    ],
}

