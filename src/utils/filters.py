# filters.py
"""
Merged AGGRESSIVE filtering module — balanced version.

Combines:
 - Critical indicator preservation (cmd.exe, payload, -enc, .dll, etc.)
 - Aggressive noise filtering (alphabet sequences, encoding labels, padding)
 - Extended domain false-positive blacklist (archive metadata, libs)
 - Conservative mutex/registry/base64 checks to avoid dropping IOCs

Design notes:
 - Keep CRITICAL_INDICATORS to avoid false negatives.
 - Merge useful extra rules from the second draft (encoding labels, locale/day names,
   alphabet sequences, extra Windows API names, archive metadata).
 - Avoid overly destructive constraints (e.g., blanket removal of domains containing
   "windows" or requiring ridiculous letter-only mutexes).
"""

import re
from typing import Dict, Any
from config.filters_config import FILTER_THRESHOLDS, FILTER_KEYWORDS

# ================================================================
# 0. GARBAGE OPERAND DETECTION (for assembly strings)
# ================================================================
def is_garbage_operand(s: str) -> bool:
    """Reject assembly operands and nonsense patterns like @$D @$D."""
    if not s or len(s) < 4:
        return True
    
    # Assembly operand patterns: @$D, $D@, etc.
    if re.search(r'[@$]{2,}', s):
        return True
    if re.fullmatch(r'[@$\s]+', s):
        return True
    
    # Mostly special chars/spaces (assembly register names)
    special_count = sum(1 for c in s if c in '@$\\-=~+')
    if special_count / len(s) > 0.5:
        return True
    
    # Only digits and separators (version-like)
    if re.fullmatch(r'[\d\s@$._-]+', s):
        return True
    
    # Very few actual letters
    letters = sum(1 for c in s if c.isalpha())
    if letters / len(s) < FILTER_THRESHOLDS['garbage_min_letters_ratio']:
        return True
    
    return False


# ================================================================
# 1. CONFIG / CRITICAL INDICATORS (preserve these ALWAYS)
# ================================================================
CRITICAL_INDICATORS = [
    # System utilities
    'cmd.exe', 'powershell.exe', 'net.exe', 'sc.exe', 'reg.exe',
    'wscript.exe', 'cscript.exe', 'msiexec.exe', 'rundll32.exe',
    'regsvr32.exe', 'schtasks.exe', 'certutil.exe', 'wmic.exe',
    'bitsadmin.exe',

    # Commands/switches
    '/c', '/k', '-enc', 'encodedcommand', 'bypass',

    # File extensions
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js',

    # Malware words
    'shellcode', 'payload', 'inject', 'malware', 'trojan',
    'ransomware', 'backdoor', 'meterpreter', 'beacon',
]


def is_critical_string(s: str) -> bool:
    """
    Return True if the string contains any critical indicator.
    Matching is case-insensitive and checks substring containment to
    preserve short switches and file names.
    """
    if not s:
        return False
    s_lower = s.lower()
    return any(ind in s_lower for ind in CRITICAL_INDICATORS)


# ================================================================
# 2. AGGRESSIVE STRING FILTERING (merged & tuned)
# ================================================================
# Keywords and encoding labels moved to FILTER_KEYWORDS

def is_real_string(s: str, min_len: int = None) -> bool:
    """
    Aggressive but IOC-safe string filter with relaxed rules for short stack strings.

    Accept if:
      - passes heuristic checks OR is a critical indicator.
      - very short mixed-character stack strings (length 2–6) are preserved.

    Reject if:
      - empty, too long (>300), or matches clear garbage heuristics.
    """
    if min_len is None:
        min_len = FILTER_THRESHOLDS['string_min_length']
    
    if not s:
        return False

    # Normalize
    if not isinstance(s, str):
        try:
            s = str(s)
        except Exception:
            return False

    length = len(s)
    if length < min_len or length > FILTER_THRESHOLDS['string_max_length']:
        return False

    s_stripped = s.strip()

    # Always preserve critical indicators
    if is_critical_string(s_stripped):
        return True

    # ----- RELAX SHORT STACK STRINGS -----
    # preserve short mixed-character strings (length 2–6) unless obvious garbage
    if 2 <= length <= 6:
        # allow if at least one letter or digit
        if any(c.isalnum() for c in s_stripped):
            # reject only if pure padding/special chars
            if re.fullmatch(r'^[Xx@#_\-=~+]{2,}$', s_stripped):
                return False
            return True

    # ----- Original heuristics for longer strings -----

    # Assembly / operand artifacts
    if re.search(r'^\$|D\$|t\$|^[A-Z][@#]|^\[.*\]|^--|\$D|@D|_@', s_stripped):
        return False

    # Short all-caps tokens (assembly mnemonics)
    if re.fullmatch(r'[A-Z]{2,6}$', s_stripped):
        return False

    # Pure hex or hex-like
    if re.fullmatch(r'[0-9A-Fa-f]+', s_stripped):
        return False

    # Pure numeric or numeric-with-punctuation
    if re.fullmatch(r'[\d\-\.,: ]+', s_stripped):
        return False

    # Reject encoding labels
    up = s_stripped.upper()
    if any(enc in up for enc in FILTER_KEYWORDS['encoding_labels']):
        return False

    # Reject repeated characters or alphabet sequences
    if re.search(r'([A-Za-z])\1{3,}', s_stripped):
        return False
    if re.search(r'ABCDEFGH|ZYXWVUTS|JKLMNOPQRST', s_stripped):
        return False

    # Reject long lowercase-only words
    if re.fullmatch(r'[a-z]{5,}', s_stripped):
        return False

    # Reject long digit runs
    if re.fullmatch(r'[0-9]{6,}', s_stripped):
        return False

    # Reject padding / repetition / special-char-only lines
    if re.match(r'^[Xx@#_\-=~+]{4,}$', s_stripped):
        return False
    if re.match(r'^[\-\=_\+\*]{4,}$', s_stripped):
        return False

    # Reject certain "garbage" words
    lower = s_stripped.lower()
    if any(bk in lower for bk in FILTER_KEYWORDS['bad_keywords']):
        return False

    # Too many special characters
    special_count = sum(1 for c in s_stripped if not c.isalnum() and c not in ' .-_/\\:@')
    if special_count / max(1, length) > FILTER_THRESHOLDS['string_max_special_ratio']:
        return False

    # Require minimum letter proportion (>=40%)
    letters = sum(1 for c in s_stripped if c.isalpha())
    if letters / length < FILTER_THRESHOLDS['string_min_letters_ratio']:
        return False

    # Require minimum alphanumeric proportion (>=30%)
    alnum = sum(1 for c in s_stripped if c.isalnum())
    if alnum / length < FILTER_THRESHOLDS['string_min_alphanumeric_ratio']:
        return False

    # Reject control characters
    if any(ord(c) < 32 for c in s_stripped):
        return False

    return True


# ================================================================
# 3. DOMAIN FILTER (merged false-positive lists, conservative rules)
# ================================================================
# Extended false-positive / archive metadata and library names moved to config

def is_real_domain(domain: str) -> bool:
    """
    Aggressive but conservative domain filter.
    Rejects obvious archive/library metadata, numeric-only or version-like domains,
    single-label names, and labels that are clearly garbage.

    Important: Do NOT reject domains containing 'windows' or 'google' entirely,
    because attackers often use believable-looking domains. Only reject explicit
    matches from the false-positive list above.
    """
    if not domain:
        return False

    d = domain.lower().strip().strip('. ')
    if len(d) < FILTER_THRESHOLDS['domain_min_length'] or len(d) > FILTER_THRESHOLDS['domain_max_length']:
        return False

    # explicit false-positive substrings
    for fp in FILTER_KEYWORDS['domain_false_positives']:
        if fp in d:
            return False

    parts = d.split('.')
    # must be at least two labels (label.tld)
    if len(parts) < 2:
        return False

    # TLD checks: alphabetic 2-6 chars (reject weird version-like tlds)
    tld = parts[-1]
    if not (2 <= len(tld) <= 6 and tld.isalpha()):
        return False

    # reject version-like full numeric dotted strings like 1.2.3.4
    if re.fullmatch(r'\d+(?:\.\d+)+', d):
        return False

    # reject any label that is a single character (a.b.c style)
    if any(len(p) == 1 for p in parts[:-1]):
        return False

    # reject labels that are pure digits
    if any(p.isdigit() for p in parts[:-1]):
        return False

    # require at least one 'meaningful' label > 4 chars
    if not any(len(p) > FILTER_THRESHOLDS['domain_label_min_length'] for p in parts[:-1]):
        return False

    # require at least one label that is mostly alpha (>60% alpha)
    if not any(sum(1 for c in p if c.isalpha()) > len(p) * FILTER_THRESHOLDS['domain_label_alpha_ratio'] for p in parts[:-1]):
        return False

    return True


# ================================================================
# 4. MUTEX FILTER (GUID acceptance + AGGRESSIVE heuristics)
# ================================================================
def is_real_mutex(s: str) -> bool:
    """
    VERY AGGRESSIVE mutex filter: Only accept high-confidence mutexes.
    Real mutexes are typically:
    - GUIDs: {UUID format}
    - Named: CamelCase+digits, snake_case, dash-separated, Global\\Name, Local\\Name
    - Mixed: AppName_v2, with underscores/dashes
    
    We REJECT:
    - Pure English words (Application, Default, Language)
    - API function names (AdjustTokenPrivileges, GetProcAddress)
    - Locale/month/day names (January, English_Australia)
    - DLL names (kernel32, user32)
    - Generic words from resources
    """
    if not s:
        return False
    s = s.strip()
    if len(s) < FILTER_THRESHOLDS['mutex_min_length'] or len(s) > FILTER_THRESHOLDS['mutex_max_length']:
        return False

    # GUIDs (accept these)
    guid = r'\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}'
    if re.search(guid, s, re.I):
        return True

    lower = s.lower()

    # AGGRESSIVE REJECTION RULES
    
    # Reject version-like patterns: 16-bit, 24-bit, 32-bit, 64-bit
    if re.match(r'^\d+-bit$', lower):
        return False
    
    # Reject pure hex (0x prefix or all hex chars)
    if lower.startswith('0x') or re.fullmatch(r'[0-9a-f]+', lower):
        return False
    
    # Reject pure digits
    if s.isdigit():
        return False
    
    # Reject backslash (assembly noise) - but allow Global\\ or Local\\ prefixes
    if '\\' in s:
        if not (s.startswith('Global\\') or s.startswith('Local\\')):
            return False
    
    # Reject @ symbol (assembly noise)
    if '@' in s:
        return False
    
    # Reject long consecutive digits (1234, 567890, etc)
    if re.search(r'\d{%d,}' % FILTER_THRESHOLDS['mutex_max_consecutive_digits'], s):
        return False
    
    # Reject repetitive single chars (aaaa, 1111, ----, etc)
    if re.match(r'^([a-z0-9\-_])\1{3,}$', lower):
        return False
    
    # ===== CRITICAL: REJECT PURE ENGLISH WORDS =====
    # These are resource strings, NOT mutexes (list moved to config)
    if lower in FILTER_KEYWORDS['english_words_to_reject']:
        return False
    
    # Reject obvious API function names
    if any(api in lower for api in ['create', 'get', 'set', 'delete', 'register', 'unregister', 'find', 'enum']):
        if not any(c in s for c in '_-'):  # unless has separator (might be real mutex)
            return False
    
    # Reject obvious false-positive patterns (list moved to config)
    if any(bk in lower for bk in FILTER_KEYWORDS['mutex_bad_keywords']):
        return False
    
    # Reject alternating digit-letter patterns (assembly noise: 0H1Q1n1, 1C1I1M1S1W1j1, etc.)
    # Pattern: mostly alternating digit-letter OR letter-digit transitions
    digit_letter_alternations = 0
    for i in range(len(s) - 1):
        if s[i].isdigit() and s[i+1].isalpha():
            digit_letter_alternations += 1
        elif s[i].isalpha() and s[i+1].isdigit():
            digit_letter_alternations += 1
    
    # If more than 50% of transitions are digit<->letter alternations = garbage pattern
    if len(s) >= 5:  # Only check for longer strings
        total_transitions = len(s) - 1
        if digit_letter_alternations / total_transitions > FILTER_THRESHOLDS['mutex_max_digit_letter_alternation']:
            return False
    
    # Require meaningful structure: 
    # - Has digits OR has underscores/dashes (real mutexes typically have these)
    # - OR is CamelCase with at least 2 case transitions
    has_digits = any(c.isdigit() for c in s)
    has_separator = any(c in s for c in '_-')
    case_transitions = sum(1 for i in range(len(s)-1) if s[i].islower() and s[i+1].isupper())
    
    if not (has_digits or has_separator or case_transitions >= FILTER_THRESHOLDS['mutex_min_case_transitions']):
        # Pure lowercase or pure words = likely garbage
        return False
    
    # Require at least some letter content
    alphas = sum(1 for c in s if c.isalpha())
    if alphas < FILTER_THRESHOLDS['mutex_min_alpha_chars']:
        return False
    
    return True


# ================================================================
# 5. REGISTRY KEY FILTER
# ================================================================
def is_real_registry_key(key: str) -> bool:
    """
    Filter registry key artifacts. Must start with HKEY_ and have plausible structure.
    """
    if not key or not isinstance(key, str):
        return False
    key = key.strip()
    if len(key) < 10 or len(key) > 260:
        return False
    if not key.startswith('HKEY_'):
        return False

    # All-caps undifferentiated garbage
    if re.fullmatch(r'[A-Z_]{20,}', key):
        return False

    # split path components and ensure not all numeric
    parts = key.split('\\')
    if len(parts) > 1 and all(p.isdigit() for p in parts[1:]):
        return False

    return True


# ================================================================
# 6. BASE64 VALIDATION
# ================================================================
def is_valid_base64(s: str, min_len: int = None) -> bool:
    """
    Validate base64-ish strings: length multiple of 4, allowed chars, and variety.
    """
    if min_len is None:
        min_len = FILTER_THRESHOLDS['base64_min_length']
    
    if not s or len(s) < min_len or len(s) % FILTER_THRESHOLDS['base64_length_multiple'] != 0:
        return False
    charset = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    if any(c not in charset for c in s):
        return False
    # require some variety (avoid AAAA.. or ffff...)
    if len(set(s)) < FILTER_THRESHOLDS['base64_min_charset_variety']:
        return False
    return True


# ================================================================
# 7. TOP-LEVEL FILTER (applies everything)
# ================================================================
def filter_indicators(indicators_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Master filter combining:
      - aggressive string filtering
      - critical indicator preservation
      - strict but conservative domain/mutex/reg/base64 filters

    Expects an indicators_dict that may contain keys:
      'ascii', 'unicode', 'stack_strings', 'domains', 'domains_prov',
      'mutexes', 'regkeys', 'base64', and others left untouched.
    """
    if not isinstance(indicators_dict, dict):
        raise TypeError("indicators_dict must be a dict")

    filtered = indicators_dict.copy()

    # ASCII strings — apply is_real_string but always keep critical indicators
    if 'ascii' in filtered and isinstance(filtered['ascii'], list):
        filtered['ascii'] = [
            s for s in filtered['ascii']
            if (is_real_string(s, min_len=2) or is_critical_string(s))
        ]

    # Unicode & stack strings — stricter minimum length (avoid short noise)
    for key in ('unicode', 'stack_strings'):
        if key in filtered and isinstance(filtered[key], list):
            # keep critical indicators even if shorter than min
            kept = []
            for s in filtered[key]:
                if is_critical_string(s):
                    kept.append(s)
                elif is_real_string(s, min_len=12) and not is_garbage_operand(s):
                    kept.append(s)
            filtered[key] = kept
    
    # Stack strings provenance — filter to match filtered stack_strings
    if 'stack_strings_prov' in filtered and filtered['stack_strings_prov']:
        try:
            filtered_stack_set = set(filtered.get('stack_strings', []))
            filtered['stack_strings_prov'] = [
                (s, sec, off) for (s, sec, off) in filtered['stack_strings_prov']
                if s in filtered_stack_set
            ]
        except Exception:
            filtered['stack_strings_prov'] = []

    # Domains
    if 'domains' in filtered and isinstance(filtered['domains'], list):
        filtered['domains'] = [d for d in filtered['domains'] if is_real_domain(d)]

    # Domain provenance tuples: (domain, section, offset) or similar
    if 'domains_prov' in filtered and filtered['domains_prov']:
        try:
            filtered['domains_prov'] = [
                (d, sec, off) for (d, sec, off) in filtered['domains_prov']
                if is_real_domain(d)
            ]
        except Exception:
            # if provenance format unexpected, attempt best-effort filter
            filtered['domains_prov'] = [
                t for t in filtered.get('domains_prov', []) if isinstance(t, tuple) and len(t) >= 1 and is_real_domain(t[0])
            ]

    # Mutexes
    if 'mutexes' in filtered and isinstance(filtered['mutexes'], list):
        filtered['mutexes'] = [m for m in filtered['mutexes'] if is_real_mutex(m)]

    # Registry keys
    if 'regkeys' in filtered and isinstance(filtered['regkeys'], list):
        filtered['regkeys'] = [rk for rk in filtered['regkeys'] if is_real_registry_key(rk)]

    # Base64 blocks
    if 'base64' in filtered and isinstance(filtered['base64'], list):
        filtered['base64'] = [b for b in filtered['base64'] if is_valid_base64(b)]

    # Note: keep URLs, IPs, decoded_c2, keywords, user_agents as-is (assumed validated elsewhere)
    return filtered
